//
//  PKCS11Wrapper.swift
//  rutoken-swift
//
//  Created by Boris Bengus on 18.01.2021.
//

import Foundation

public class PKCS11Wrapper {
    static let shared = PKCS11Wrapper()
    
    private var isMonitoringStarted = false
    
    /// Контекст Libp11
    private var ctx: UnsafeMutablePointer<PKCS11_CTX>
    /// Сохраненные слоты
    private var storedNSlots: UInt32 = 0
    private var storedSlots: UnsafeMutablePointer<PKCS11_SLOT>?
    /// Сохраненные сертификаты и приватные ключи активного токена.
    /// Ни в коем случае не стоит отдельно освобождать эти объекты. Их высвободит releaseSlots().
    /// Допускается зануление самого MutablePointer
    private var storedNCerts: UInt32 = 0
    private var storedCerts: UnsafeMutablePointer<PKCS11_CERT>?
    private var storedNPKeys: UInt32 = 0
    private var storedPKeys: UnsafeMutablePointer<PKCS11_KEY>?
    /// Мапа пинов по ключу serialNumber токена
    private var lastUsedPinMap = [String : String]()
    
    // Очереди работы для корректной многопоточности
    private let monitoringQueue = DispatchQueue(
        label: "ru.eaasoft.plugins.RutokenPlugin.TokenMonitoringQueue",
        attributes: .concurrent
    )
    private let serialQueue = DispatchQueue(label: "ru.eaasoft.plugins.RutokenPlugin.TokenSerialQueue")
    private let callbackQueue = DispatchQueue.main
    
    // Колбэки мониторинга
    private var onTokenAdd: ((TokenDto) -> Void)?
    private var onTokenRemove: ((SlotDto) -> Void)?
    
    private init() {
        ctx = PKCS11_CTX_new()
        
        var r: Int32 = -1
        
        // загружаем pkcs #11 модуль
        // Внутри PKCS11_CTX_load вся инициализация engine (C_LoadModule, C_Initialize)
        // Вторым параметром требуется имя модуля pkcs11 для openssl. Внезапно прокатило указание rtpkcs11ecp
        // По нему внутри он делает dlopen и подгрузку динамической библиотеки
        r = PKCS11_CTX_load(ctx, "rtpkcs11ecp.framework/rtpkcs11ecp")
        guard r == 0 else {
            fputs("loading pkcs11 engine failed:\n", stderr)
            ERR_print_errors_fp(stderr)
            fatalError()
        }
    }
    
    deinit {
        // освободим все слоты, закроем сессии
        releaseSlots()
        // Внутри PKCS11_CTX_unload все освобождение engine (C_Finalize, C_UnloadModule)
        PKCS11_CTX_unload(ctx)
        PKCS11_CTX_free(ctx)
    }
    
    
    // MARK: - Private
    private func releaseSlots() {
        PKCS11_release_all_slots(ctx, storedSlots, storedNSlots)
        self.storedSlots = nil
        self.storedNSlots = 0
        invalidateCertsAndKeys()
    }
    
    private func invalidateCertsAndKeys() {
        self.storedCerts = nil
        self.storedNCerts = 0
        self.storedPKeys = nil
        self.storedNPKeys = 0
    }
    
    private func updateStoredSlots() throws {
        if storedSlots != nil {
            releaseSlots()
        }
        
        let r = PKCS11_enumerate_slots(ctx, &storedSlots, &storedNSlots)
        guard r == 0 else {
            fputs("enumerating pkcs11 slots failed:\n", stderr)
            ERR_print_errors_fp(stderr)
            throw PKCS11Error.enumeratingSlotsFailed
        }
    }
    
    private func updateStoredCerts() throws {
        // вертаем первый слот с подключенным токеном
        guard let activeSlot = PKCS11_find_token(ctx, storedSlots, storedNSlots) else {
            // при отсутствии активного слота с токеном, занулим сохраненные сертификаты
            storedCerts = nil
            storedNCerts = 0
            return
        }
        
        let r = PKCS11_enumerate_certs(activeSlot.pointee.token, &storedCerts, &storedNCerts)
        guard r == 0 else {
            fputs("enumerating certs failed:\n", stderr)
            ERR_print_errors_fp(stderr)
            throw PKCS11Error.enumeratingCertificatesFailed
        }
    }
    
    private func updateStoredPKeys() throws {
        // вертаем первый слот с подключенным токеном
        guard let activeSlot = PKCS11_find_token(ctx, storedSlots, storedNSlots) else {
            // при отсутствии активного слота с токеном, занулим сохраненные ключи
            storedPKeys = nil
            storedNPKeys = 0
            return
        }
        
        // получаем приватные ключи
        let r = PKCS11_enumerate_keys(activeSlot.pointee.token, &storedPKeys, &storedNPKeys)
        guard r == 0 else {
            fputs("enumerating private keys failed:\n", stderr)
            ERR_print_errors_fp(stderr)
            throw PKCS11Error.enumeratingKeysFailed
        }
    }
    
    private func getX509ByCkaId(_ ckaId: String) -> OpaquePointer? {
        guard let storedCerts = storedCerts else { return nil }
        for i in 0..<Int(self.storedNCerts) {
            if
                let id = String.fromUInt8(storedCerts[i].id),
                id.lowercased() == ckaId.lowercased(),
                let x509 = storedCerts[i].x509
            {
                return x509
            }
        }
        
        return nil
    }
    
    private func getEvpPKeyByCkaId(_ ckaId: String) -> OpaquePointer? {
        guard let storedPKeys = storedPKeys else { return nil }
        for i in 0..<Int(self.storedNPKeys) {
            if
                let id = String.fromUInt8(storedPKeys[i].id),
                id.lowercased() == ckaId.lowercased(),
                let evpPKey = PKCS11_get_private_key(&storedPKeys[i])
            {
                return evpPKey
            }
        }
        
        return nil
    }
    
    private func performLogin(
        pin: String,
        slot: UnsafeMutablePointer<PKCS11_SLOT>
    ) throws {
        let serial = String.fromInt8(slot.pointee.token.pointee.serialnr)
        let r = PKCS11_login(slot, 0, pin)
        guard r == 0 else {
            fputs("login pkcs11 failed:\n", stderr)
            ERR_print_errors_fp(stderr)
            // Удаляем пин из хэшмапы по ключу серийника токена (см. checkLogin)
            if let serial = serial {
                lastUsedPinMap.removeValue(forKey: serial)
            }
            throw PKCS11Error.loginFailed
        }
        // Сохраняем пин код в хэшмапу по ключу серийника токена (см. checkLogin)
        if let serial = serial {
            lastUsedPinMap[serial] = pin
        }
    }
    
    private func checkLogin(slot: UnsafeMutablePointer<PKCS11_SLOT>) throws {
        // Если находим сохраненный пин, тогда пробуем логиниться, иначе валимся.
        guard
            let serial = String.fromInt8(slot.pointee.token.pointee.serialnr),
            let pin = lastUsedPinMap[serial] else
        {
            throw PKCS11Error.loginRequired
        }
        
        try performLogin(
            pin: pin,
            slot: slot
        )
    }
    
    private func getTokenDtos() -> [TokenDto] {
        guard let slots = storedSlots else { return [] }
        
        var tokenDtos = [TokenDto]()
        for i in 0..<Int(storedNSlots) {
            if slots[i].token != nil {
                let dto = TokenDto(from: &slots[i])
                tokenDtos.append(dto)
            }
        }
        
        return tokenDtos
    }
    
    private func getCertificateDtos() -> [CertificateDto] {
        guard let certs = storedCerts else { return [] }
        
        var certificateDtos = [CertificateDto]()
        for i in 0..<Int(storedNCerts) {
            let dto = CertificateDto(from: &certs[i])
            certificateDtos.append(dto)
        }
        
        return certificateDtos
    }
    
    
    // MARK: - Public
    public func getTokens(completion: @escaping (Result<[TokenDto], PKCS11Error>) -> Void) {
        serialQueue.async {
            do {
                try self.updateStoredSlots()
                let tokenDtos = self.getTokenDtos()
                self.callbackQueue.async {
                    completion(.success(tokenDtos))
                }
            } catch {
                self.callbackQueue.async {
                    let wrappedError = PKCS11Error.wrapError(error)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
    
    public func getCertificates(completion: @escaping (Result<[CertificateDto], PKCS11Error>) -> Void) {
        serialQueue.async {
            do {
                // Лениво подгрузим сертификаты
                if self.storedCerts == nil {
                    try self.updateStoredCerts()
                }
                let dtos = self.getCertificateDtos()
                self.callbackQueue.async {
                    completion(.success(dtos))
                }
            } catch {
                self.callbackQueue.async {
                    let wrappedError = PKCS11Error.wrapError(error)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
    
    public func login(
        pin: String,
        completion: @escaping (Result<Void, PKCS11Error>) -> Void
    ) {
        serialQueue.async {
            do {
                // вертаем первый слот с подключенным токеном
                guard let activeSlot = PKCS11_find_token(self.ctx, self.storedSlots, self.storedNSlots) else {
                    // при отсутствии активного слота с токеном валимся
                    throw PKCS11Error.tokenDisconnected
                }
                
                try self.performLogin(
                    pin: pin,
                    slot: activeSlot
                )
                self.callbackQueue.async {
                    completion(.success(()))
                }
            } catch {
                self.callbackQueue.async {
                    let wrappedError = PKCS11Error.wrapError(error)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
    
    public func stopMonitoring() {
        guard isMonitoringStarted else { return }
        
        isMonitoringStarted = false
        onTokenAdd = nil
        onTokenRemove = nil
    }
    
    public func startMonitoring(
        onTokenAdd: @escaping (TokenDto) -> Void,
        onTokenRemove: @escaping (SlotDto) -> Void
    ) {
        guard !isMonitoringStarted else { return }
        
        self.onTokenAdd = onTokenAdd
        self.onTokenRemove = onTokenRemove
        isMonitoringStarted = true
        
        monitoringQueue.async {
            while self.isMonitoringStarted {
                var eventSlotId: UInt = 0
                var r: Int32 = -1
                
                r = PKCS11_wait_for_slot_event(self.ctx, &eventSlotId)
                guard r == 0 else {
                    fatalError() // TODO: onMonitoringError: @escaping (Libp11Error) -> Void
                }
                
                self.serialQueue.sync {
                    if let storedSlots = self.storedSlots {
                        // Если ранее слоты были загружены, то просто переинициализируем слот с нужным айди
                        r = PKCS11_reinit_slot(self.ctx, storedSlots, self.storedNSlots, eventSlotId)
                        guard r == 0 else {
                            self.releaseSlots()
                            fatalError() // TODO: onMonitoringError: @escaping (Libp11Error) -> Void
                        }
                        // После успешной переинициализации слота, инвалидируем сертификаты и ключи
                        self.invalidateCertsAndKeys()
                    } else {
                        // Если ранее слоты не загружали, то просто получим их
                        try! self.updateStoredSlots()
                    }
                    
                    guard let storedSlots = self.storedSlots else {
                        self.releaseSlots()
                        // TODO: onMonitoringError: @escaping (Libp11Error) -> Void
                        fatalError() // невозможно не загрузить слоты при корректной работе PKCS#11
                    }
                    // Поищем слот из ивента
                    var eventSlot: PKCS11_SLOT!
                    for i in 0..<Int(self.storedNSlots) {
                        if PKCS11_get_slotid_from_slot(&storedSlots[i]) == eventSlotId {
                            eventSlot = storedSlots[i]
                            break
                        }
                    }
                    guard eventSlot != nil else {
                        self.releaseSlots()
                        // TODO: onMonitoringError: @escaping (Libp11Error) -> Void
                        fatalError() // невозможно получить событие от несуществующего слота
                    }
                    
                    // Если в слоте ивента предатсвлен токен, то add, иначе remove
                    if eventSlot.token != nil {
                        let dto = TokenDto(from: &eventSlot)
                        self.callbackQueue.async {
                            self.onTokenAdd?(dto)
                        }
                    } else {
                        let dto = SlotDto(from: &eventSlot)
                        self.callbackQueue.async {
                            self.onTokenRemove?(dto)
                        }
                    }
                    
                }
            }
        }
    }
    
    public func cmsEncrypt(
        _ data: Data,
        recipientPems: [Data],
        completion: @escaping (Result<Data, PKCS11Error>) -> Void
    ) {
        serialQueue.async {
            do {
                // стек сертификатов получателей
                guard let recipientsX509Stack = sk_X509_new_null() else {
                    throw PKCS11Error.generalError
                }
                for pemData in recipientPems {
                    try pemData.withUnsafeBytes {
                        var pointer: UnsafePointer<UInt8>? = $0.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        guard let x509 = d2i_X509(nil, &pointer, pemData.count) else {
                            throw PKCS11Error.generalError
                        }
                        sk_X509_push(recipientsX509Stack, x509)
                    }
                }
                defer {
                    sk_X509_pop_free(recipientsX509Stack, X509_free)
                }
                
                let encryptedData = try CMSData.cmsEncrypt(
                    data,
                    recipientsX509Stack: recipientsX509Stack
                )
                self.callbackQueue.async {
                    completion(.success(encryptedData))
                }
            } catch {
                self.callbackQueue.async {
                    let wrappedError = PKCS11Error.wrapError(error)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
    
    public func cmsDecrypt(
        ckaId: String,
        data: Data,
        completion: @escaping (Result<Data, PKCS11Error>) -> Void
    ) {
        serialQueue.async {
            do {
                // вертаем первый слот с подключенным токеном
                guard let activeSlot = PKCS11_find_token(self.ctx, self.storedSlots, self.storedNSlots) else {
                    // при отсутствии активного слота с токеном валимся
                    throw PKCS11Error.tokenDisconnected
                }
                // проверим логин на токене
                try self.checkLogin(slot: activeSlot)
                // Лениво подгрузим сертификаты и приватные ключи
                if self.storedCerts == nil {
                    try self.updateStoredCerts()
                }
                if self.storedPKeys == nil {
                    try self.updateStoredPKeys()
                }
                guard
                    let x509 = self.getX509ByCkaId(ckaId),
                    let evpPKey = self.getEvpPKeyByCkaId(ckaId) else
                {
                    throw PKCS11Error.keyPairNotFound
                }
                
                let decryptedData = try CMSData.cmsDecrypt(
                    data,
                    x509: x509,
                    evpPKey: evpPKey
                )
                self.callbackQueue.async {
                    completion(.success(decryptedData))
                }
            } catch {
                self.callbackQueue.async {
                    let wrappedError = PKCS11Error.wrapError(error)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
    
    public func cmsSign(
        ckaId: String,
        data: Data,
        completion: @escaping (Result<Data, PKCS11Error>) -> Void
    ) {
        serialQueue.async {
            do {
                // вертаем первый слот с подключенным токеном
                guard let activeSlot = PKCS11_find_token(self.ctx, self.storedSlots, self.storedNSlots) else {
                    // при отсутствии активного слота с токеном валимся
                    throw PKCS11Error.tokenDisconnected
                }
                // проверим логин на токене
                try self.checkLogin(slot: activeSlot)
                // Лениво подгрузим сертификаты и приватные ключи
                if self.storedCerts == nil {
                    try self.updateStoredCerts()
                }
                if self.storedPKeys == nil {
                    try self.updateStoredPKeys()
                }
                guard
                    let x509 = self.getX509ByCkaId(ckaId),
                    let evpPKey = self.getEvpPKeyByCkaId(ckaId) else
                {
                    throw PKCS11Error.keyPairNotFound
                }
                
                let signedData = try CMSData.cmsSign(
                    data,
                    x509: x509,
                    evpPKey: evpPKey
                )
                self.callbackQueue.async {
                    completion(.success(signedData))
                }
            } catch {
                self.callbackQueue.async {
                    let wrappedError = PKCS11Error.wrapError(error)
                    completion(.failure(wrappedError))
                }
            }
        }
    }
}

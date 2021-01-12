package ru.rutoken.pkcs11caller;

import ru.rutoken.pkcs11caller.exception.Pkcs11CallerException;

public class Pkcs11Result {
    Pkcs11CallerException exception;
    Object[] arguments;

    public Pkcs11Result(Object... arguments) {
        this.arguments = arguments;
    }

    Pkcs11Result(Pkcs11CallerException exception) {
        this.exception = exception;
    }
}

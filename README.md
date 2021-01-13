# cordova-plugin-rutoken


#Method getTokens 
```
window.plugins.rutoken.getTokens(
    function(tokens){
        var jsonTokens = JSON.parse(tokens);
        if(jsonTokens.length > 0)
            setToken(jsonTokens[0]);
    },
    function(error){
        alert(error);
    }
);
```

#Method waitForSlotEvent (Event token connect/ disconnect)
```
window.plugins.rutoken.waitForSlotEvent(
    function(event){
        var jsonEvent = JSON.parse(event);
        if(jsonEvent.event == 'add')
            setToken(jsonEvent.tokenInfo);
        else
            clearToken();
    },
    function(eventError){
        console.log(eventError);
    }
);
```

#Method getCertificates 
```
window.plugins.rutoken.getCertificates(
    {slotId: '"slotId" from function "getTokens" or "waitForSlotEvent"'},
    function(certificates){
        console.log(certificates);
    },
    function(error){
        alert(error);
    }
);
```


#Method cmsSign
```
window.plugins.rutoken.cmsSign({
        slotId: '"slotId" from function "getTokens" or "waitForSlotEvent"',
        pin:'',
        ckaId:'"Cka Id" from function "getCertificates"',
        data:'hello',
    },
    function(cmsSign){
        console.log(cmsSign);
    },
    function(error){
        alert(error)
    }
);
```

#Method cmsEncrypt
```
window.plugins.rutoken.cmsEncrypt({
        slotId: '"slotId" from function "getTokens" or "waitForSlotEvent"',
        pin:'',
        ckaId:'"Cka Id" from function "getCertificates"',
        data:'hello',
    },
    function(encData){
        console.log(encData);
    },
    function(error){
        alert(error)
    }
);
```

#Method cmsDecrypt
```
 window.plugins.rutoken.cmsDecrypt({
        slotId: '"slotId" from function "getTokens" or "waitForSlotEvent"',
        pin:'',
        ckaId:'"Cka Id" from function "getCertificates"',
        data:encData,
    },
    function(data){
        console.log(data);
    },
    function(error){
        alert(error)
    }
);
```
package com.example.springboot;

import dev.samstevens.totp.exceptions.QrGenerationException;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.Base64;

@RestController
public class HelloController {

    @Autowired
    TotpService totpService;

    private String userKey;

    @GetMapping("/bind")
    public ResponseEntity mfa() throws QrGenerationException {

        String key = totpService.generateSecretKey();

        //这一步，把user key存到user的数据库和REDIS, 而不是放到内存，大家共享哈
        this.userKey = key;
        //saveToDB(userKey);
        //saveToDB(MFA_STATUS.BINDING);


        byte[] code = totpService.generateQrCode(key);
        MediaType mediaType = MediaType.IMAGE_PNG;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(mediaType);
        headers.setContentLength(code.length);
        headers.set("key", key);
        return new ResponseEntity<>(code, headers, HttpStatus.OK);
    }

    @GetMapping("/mfa-enabled")
    public Enum enabled() throws QrGenerationException {

        //从数据库获取 MFA_STATUS, 并返回
        // Return MFA_STATUS
        return Strings.isBlank(userKey)? MFA_STATUS.NON : MFA_STATUS.BOUND;
    }


    @PostMapping("/verify")
    public Enum mfa(@RequestParam String code) {
        boolean result = totpService.verifyTotpCode(userKey, code);
        if (result == true){
            //set MFA_STATUS = bound
            //saveBind(user, MFA_STATUS.BOUND)
            return  MFA_STATUS.BOUND;
        }
        else {
            return MFA_STATUS.FAILED;
        }

    }


}

package com.example.springboot;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Component;

@Component
public class TotpService {
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();

    public String generateSecretKey() {
        return secretGenerator.generate();
    }

    public byte[] generateQrCode(String secret) throws QrGenerationException {
        QrData data = new QrData.Builder()
                .label("调诉宝")
                .secret(secret)
                .issuer("调诉宝")
                .algorithm(HashingAlgorithm.SHA1) // or SHA256, SHA512
                .digits(6)
                .period(30)
                .build();
        QrGenerator qrGenerator = new ZxingPngQrGenerator();
        return qrGenerator.generate(data);
    }


    public boolean verifyTotpCode(String secret, String totpCode) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator,timeProvider);
        return verifier.isValidCode(secret, totpCode);
    }
}

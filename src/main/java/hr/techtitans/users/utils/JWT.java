package hr.techtitans.users.utils;

import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JWT {
    public String generateToken(String username, String userRole, String userId) {
        try {
            Map<String, Object> headerClaims = new HashMap<>();
            Map<String, Object> payloadClaims = new HashMap<>();

            payloadClaims.put("username", username);
            payloadClaims.put("role", userRole);
            payloadClaims.put("userId", userId);

            //1 day
            Date expiresAt = new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000);
            payloadClaims.put("expire", expiresAt);
            System.out.println("TEST"+payloadClaims);

            Method initMethod = JWTCreator.class.getDeclaredMethod("init");
            initMethod.setAccessible(true);
            JWTCreator.Builder builder = (JWTCreator.Builder) initMethod.invoke(null);

            builder.withHeader(headerClaims);
            builder.withPayload(payloadClaims);
            String secretKey = "J32DS8923ND78921NJD72430DSNsg42";
            return builder.sign(Algorithm.HMAC256(secretKey));
        } catch (Exception e) {
            return null;
        }
    }
}

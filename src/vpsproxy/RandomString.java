package vpsproxy;

import java.security.SecureRandom;
import java.util.Random;

public class RandomString {
    private static final String ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final Random RANDOM = new SecureRandom();

    public static String generate(int n) {
        StringBuilder sb = new StringBuilder(6);
        for (int i = 0; i < n; i++) {
            int randomIndex = RANDOM.nextInt(ALPHABET.length());
            char randomChar = ALPHABET.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }
}

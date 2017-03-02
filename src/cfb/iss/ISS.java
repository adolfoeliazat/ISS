package cfb.iss;

import cfb.curl.Curl;

/**
 * (c) 2016 Come-from-Beyond
 */
public class ISS {

    private static final int MIN_TRIT_VALUE = -1, MAX_TRIT_VALUE = 1;
    private static final int TRYTE_WIDTH = 3;
    private static final int MIN_TRYTE_VALUE = -13, MAX_TRYTE_VALUE = 13;
    private static final int SUBSEED_LENGTH = Curl.HASH_LENGTH;
    private static final int KEY_LENGTH = (Curl.HASH_LENGTH / TRYTE_WIDTH + 1) * Curl.HASH_LENGTH;
    private static final int DIGEST_LENGTH = Curl.HASH_LENGTH;
    private static final int ADDRESS_LENGTH = Curl.HASH_LENGTH;
    private static final int BUNDLE_LENGTH = Curl.HASH_LENGTH;
    private static final int SIGNATURE_LENGTH = KEY_LENGTH;
    private static final int CHECKSUM_LENGTH = Curl.HASH_LENGTH;
    private static final int MAX_CHECKSUM_VALUE = Curl.HASH_LENGTH / TRYTE_WIDTH * (MAX_TRYTE_VALUE - MIN_TRYTE_VALUE);

    public static int[] subseed(final int[] seed, int index) {

        if (index < 0) {

            throw new RuntimeException("Invalid subseed index: " + index);
        }

        final int[] subseedPreimage = new int[seed.length];
        System.arraycopy(seed, 0, subseedPreimage, 0, subseedPreimage.length);

        while (index-- > 0) {

            for (int i = 0; i < subseedPreimage.length; i++) {

                if (++subseedPreimage[i] > MAX_TRIT_VALUE) {

                    subseedPreimage[i] = MIN_TRIT_VALUE;

                } else {

                    break;
                }
            }
        }

        final int[] subseed = new int[SUBSEED_LENGTH];

        final Curl curl = new Curl();
        curl.absorb(subseedPreimage, 0, subseedPreimage.length);
        curl.squeeze(subseed, 0, subseed.length);

        return subseed;
    }

    public static int[] key(final int[] subseed) {

        final int[] key = new int[KEY_LENGTH];

        final Curl curl = new Curl();
        curl.absorb(subseed, 0, subseed.length);
        curl.squeeze(key, 0, key.length);
        for (int offset = 0; offset < key.length; offset += Curl.HASH_LENGTH) {

            curl.reset();
            curl.absorb(key, offset, Curl.HASH_LENGTH);
            curl.squeeze(key, offset, Curl.HASH_LENGTH);
        }

        return key;
    }

    public static int[] digest(final int[] key) {

        if (key.length != KEY_LENGTH) {

            throw new RuntimeException("Invalid key length: " + key.length);
        }

        final Curl digestCurl = new Curl();

        final int[] buffer = new int[Curl.HASH_LENGTH];
        final Curl keyFragmentCurl = new Curl();

        for (int i = 0; i < (KEY_LENGTH - CHECKSUM_LENGTH) / Curl.HASH_LENGTH; i++) {

            System.arraycopy(key, i * Curl.HASH_LENGTH, buffer, 0, buffer.length);
            for (int j = MAX_TRYTE_VALUE - MIN_TRYTE_VALUE; j-- > 0; ) {

                keyFragmentCurl.reset();
                keyFragmentCurl.absorb(buffer, 0, buffer.length);
                keyFragmentCurl.squeeze(buffer, 0, buffer.length);
            }
            digestCurl.absorb(buffer, 0, Curl.HASH_LENGTH);
        }

        System.arraycopy(key, KEY_LENGTH - CHECKSUM_LENGTH, buffer, 0, buffer.length);
        for (int i = MAX_CHECKSUM_VALUE; i-- > 0; ) {

            keyFragmentCurl.reset();
            keyFragmentCurl.absorb(buffer, 0, buffer.length);
            keyFragmentCurl.squeeze(buffer, 0, buffer.length);
        }
        digestCurl.absorb(buffer, 0, CHECKSUM_LENGTH);

        final int[] digest = new int[DIGEST_LENGTH];
        digestCurl.squeeze(digest, 0, digest.length);

        return digest;
    }

    public static int[] address(final int[] digests) {

        if (digests.length % DIGEST_LENGTH != 0) {

            throw new RuntimeException("Invalid digests length: " + digests.length);
        }

        final int[] address = new int[ADDRESS_LENGTH];

        final Curl curl = new Curl();
        curl.absorb(digests, 0, digests.length);
        curl.squeeze(address, 0, address.length);

        return address;
    }

    public static int[] signature(final int[] bundle, final int[] key) {

        if (bundle.length != BUNDLE_LENGTH) {

            throw new RuntimeException("Invalid bundle length: " + bundle.length);
        }
        if (key.length != KEY_LENGTH) {

            throw new RuntimeException("Invalid key length: " + key.length);
        }

        final int[] signature = new int[SIGNATURE_LENGTH];
        System.arraycopy(key, 0, signature, 0, signature.length);

        int checksumValue = MAX_CHECKSUM_VALUE;
        final Curl curl = new Curl();

        for (int i = 0; i < (SIGNATURE_LENGTH - CHECKSUM_LENGTH) / Curl.HASH_LENGTH; i++) {

            final int hashingChainLength = MAX_TRYTE_VALUE - (bundle[i * TRYTE_WIDTH] + bundle[i * TRYTE_WIDTH + 1] * 3 + bundle[i * TRYTE_WIDTH + 2] * 9);
            checksumValue -= hashingChainLength;
            for (int j = hashingChainLength; j-- > 0; ) {

                curl.reset();
                curl.absorb(signature, i * Curl.HASH_LENGTH, Curl.HASH_LENGTH);
                curl.squeeze(signature, i * Curl.HASH_LENGTH, Curl.HASH_LENGTH);
            }
        }

        while (checksumValue-- > 0) {

            curl.reset();
            curl.absorb(signature, SIGNATURE_LENGTH - CHECKSUM_LENGTH, Curl.HASH_LENGTH);
            curl.squeeze(signature, SIGNATURE_LENGTH - CHECKSUM_LENGTH, Curl.HASH_LENGTH);
        }

        return signature;
    }

    public static int[] digest(final int[] bundle, final int[] signature) {

        if (bundle.length != BUNDLE_LENGTH) {

            throw new RuntimeException("Invalid bundle length: " + bundle.length);
        }
        if (signature.length != SIGNATURE_LENGTH) {

            throw new RuntimeException("Invalid signature length: " + signature.length);
        }

        final Curl digestCurl = new Curl();

        final int[] buffer = new int[Curl.HASH_LENGTH];
        int checksumValue = MAX_CHECKSUM_VALUE;
        final Curl signatureFragmentCurl = new Curl();

        for (int i = 0; i < (SIGNATURE_LENGTH - CHECKSUM_LENGTH) / Curl.HASH_LENGTH; i++) {

            System.arraycopy(signature, i * Curl.HASH_LENGTH, buffer, 0, buffer.length);
            final int hashingChainLength = (bundle[i * TRYTE_WIDTH] + bundle[i * TRYTE_WIDTH + 1] * 3 + bundle[i * TRYTE_WIDTH + 2] * 9) - MIN_TRYTE_VALUE;
            checksumValue -= hashingChainLength;
            for (int j = hashingChainLength; j-- > 0; ) {

                signatureFragmentCurl.reset();
                signatureFragmentCurl.absorb(buffer, 0, buffer.length);
                signatureFragmentCurl.squeeze(buffer, 0, buffer.length);
            }
            digestCurl.absorb(buffer, 0, buffer.length);
        }

        System.arraycopy(signature, SIGNATURE_LENGTH - CHECKSUM_LENGTH, buffer, 0, buffer.length);
        while (checksumValue-- > 0) {

            signatureFragmentCurl.reset();
            signatureFragmentCurl.absorb(buffer, 0, buffer.length);
            signatureFragmentCurl.squeeze(buffer, 0, buffer.length);
        }
        digestCurl.absorb(buffer, 0, buffer.length);

        final int[] digest = new int[DIGEST_LENGTH];
        digestCurl.squeeze(digest, 0, digest.length);

        return digest;
    }
}

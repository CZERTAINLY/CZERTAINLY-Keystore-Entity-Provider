package com.czertainly.provider.entity.keystore;

import com.czertainly.provider.entity.keystore.command.KeystoreCertificate;
import com.czertainly.provider.entity.keystore.util.KeystoreResponseUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

public class KeystoreResponseTest {

    private static final String response = "Keystore type: jks\n" +
            "Keystore provider: SUN\n" +
            "\n" +
            "Your keystore contains 3 entries\n" +
            "\n" +
            "Alias name: letsencrypt\n" +
            "Creation date: Nov 16, 2019\n" +
            "Entry type: trustedCertEntry\n" +
            "\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\n" +
            "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" +
            "DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\n" +
            "SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\n" +
            "GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\n" +
            "q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\n" +
            "SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\n" +
            "Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\n" +
            "a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n" +
            "/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\n" +
            "AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\n" +
            "CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\n" +
            "bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\n" +
            "c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\n" +
            "VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\n" +
            "ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\n" +
            "MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\n" +
            "Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\n" +
            "AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\n" +
            "uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\n" +
            "wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\n" +
            "X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\n" +
            "PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\n" +
            "KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\n" +
            "-----END CERTIFICATE-----\n" +
            "\n" +
            "\n" +
            "*******************************************\n" +
            "*******************************************\n" +
            "\n" +
            "\n" +
            "Alias name: letsencryptcert\n" +
            "Creation date: Nov 16, 2019\n" +
            "Entry type: trustedCertEntry\n" +
            "\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFcTCCBFmgAwIBAgISAyeoQB+VVtFW7aIlaxbbC90WMA0GCSqGSIb3DQEBCwUA\n" +
            "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n" +
            "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTExMTYxMjQ3MzNaFw0y\n" +
            "MDAyMTQxMjQ3MzNaMB0xGzAZBgNVBAMTEmxhYjAxLjNrZXkuY29tcGFueTCCASIw\n" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKt8hJSHW5XtgFEBpAYzSOZL0m52\n" +
            "/reCljycBANvUzj+Eu+/yehTZgX2bs9+gInngnwENTBfD9SdAVyEKm5VhCtRNgy2\n" +
            "8OcjAfywI+rJfN9S4riW16O2bO2enLsVOVbtirgNJsjaCaJ6e7yjWdRhSUady6gL\n" +
            "n8870NeaSqCngYdC9YLs82ZYaVwh6glGJnib8iL/OzJF+KICxwNIGdbyKGoFneDR\n" +
            "1NXVDCoSJ5HObhbkYQeSJSjssI3ubW3Exr0vRZ3fhAy9Jd19IsFnNfjebBmcn0Mm\n" +
            "QIOJBYk4RnQ81r/BBb5entfSK2AywyNCIXTynpI6sWnhhKPmD5MsdiLZF1cCAwEA\n" +
            "AaOCAnwwggJ4MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\n" +
            "KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUouvsU1fpmDwRnipgBhGt\n" +
            "XlorIwowHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUH\n" +
            "AQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5\n" +
            "cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5\n" +
            "cHQub3JnLzAyBgNVHREEKzApghJsYWIwMS4za2V5LmNvbXBhbnmCE3NzZGVtby4z\n" +
            "a2V5LmNvbXBhbnkwTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMBAQEw\n" +
            "KDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEEBgor\n" +
            "BgEEAdZ5AgQCBIH1BIHyAPAAdwDwlaRZ8gDRgkAQLS+TiI6tS/4dR+OZ4dA0prCo\n" +
            "qo6ycwAAAW50eAkAAAAEAwBIMEYCIQD2+WtHbimME4bp8XUUnF0g2hVFp8FVHXyH\n" +
            "4VUCwU6HzgIhAKECmgq1tIQbEPoSnnZrJ4AbT0MFOgjBg2ICsXArkJArAHUAsh4F\n" +
            "zIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4AAAFudHgI8QAABAMARjBEAiAY\n" +
            "OarmYNsMV6tNoEI9II/xHuwVP3TRZ4rmjveRazryUAIgGVsBXl2NTZY8aTeoLbej\n" +
            "1QNgVlK8STG+DwRt+rTCb2AwDQYJKoZIhvcNAQELBQADggEBACsHc0PHweBP9zGN\n" +
            "Oz3oqg+najT7jApupTFSIRi4x5EOdxNKcu79n6nWZuVlMaflkzaKVQ6Ega2+Ag/5\n" +
            "QgVfj9XbBlgCK1GfMN9zLYlwSKk6nof3aWBSlzlAx93Eu+poqiIdrmMNkHD819DW\n" +
            "mZsritaQwXsTlNpf3HXggZIsnJNs8yLGEH9Lt0h+4WJXHhAPjp+fuYDGsKai3Zuc\n" +
            "0BF1WyE4QStBjW751rDNDWL8H6ywCj6S9leIpHtZVCoRE98h3Qz/r43cBpNwlIuX\n" +
            "O1aRg/kJeSwlncq0vJ1h8hFDHoddyBtrZGXfumpPz287toYnMpJx1EsOOm8Mhe/U\n" +
            "cWgt2Uc=\n" +
            "-----END CERTIFICATE-----\n" +
            "\n" +
            "\n" +
            "*******************************************\n" +
            "*******************************************\n" +
            "\n" +
            "\n" +
            "Alias name: managementca\n" +
            "Creation date: May 8, 2019\n" +
            "Entry type: trustedCertEntry\n" +
            "\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFcDCCA1igAwIBAgIUQ8qEcLshApVCEh1+wrszGBW9mHEwDQYJKoZIhvcNAQEL\n" +
            "BQAwNjEWMBQGA1UEAwwNTWFuYWdlbWVudCBDQTEcMBoGA1UECgwTM0tleSBDb21w\n" +
            "YW55IHMuci5vLjAeFw0xOTA1MDgxMjUxNTZaFw0yOTA1MDUxMjUxNTZaMDYxFjAU\n" +
            "BgNVBAMMDU1hbmFnZW1lbnQgQ0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIu\n" +
            "by4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDZ3+k1GPIGkimNd9ME\n" +
            "w9cWCYYzUh11mv5NVJsw+uRbzxQsP7oqeQQdMxHqhSP0eGg6UxqQ6PQSCCkHvMtr\n" +
            "pFGX+eMZuB/z1vFodHdBCUTNOUr6c0c+wMGuhJoYPAwY/OW5YDrw6r1oxtKbbD7H\n" +
            "MOPE1tt5twGQTuy4BBQEWp/SSHs39UoDtLqbLwzuekv1GcQxCjWpHjX5fIbIf7JZ\n" +
            "fXrQ8WnMkHInbow9tQIAOtKyDJ32Y2DUSgK4v1zp0UtnABXBaVyih3am/Sghv6RL\n" +
            "jP0xEnWpRtAt4HqtSFFMVCEkgqIEU7Ev9eTuGJvy76lvvrPpr5dow35FWz8tZcPw\n" +
            "PwXKMqaHRPPIjS3HDKi/BOmqOGpnANcJyn4X+/NsOTNkIXLAj9H5t4deQR4jckSw\n" +
            "NcPeh/5zXgqmPU5GLhhis+zu0TxfMKuEovXHOWlfiyU4Xzx6MAsjb9dPRqjR2ku7\n" +
            "TNc9megR7yDV809eOa6M5roVZB2L71/rKKkzLS/u9kImShhtqlxQ9XckN0Op2Gpp\n" +
            "PYIO8rzmZHzCv+gb/NIeVZ+UbTIbANA3NYXWjJlMzgyf/Dub0vZbhRxLpKRcziOZ\n" +
            "N8STB8p+d6kChct1u10SZwQglMUM8WPo8t+CHPw/AvApdwD2z45CktFiR6V83gqv\n" +
            "qGdDkaCg/CdpnzltHN/Zr4NDpwIDAQABo3YwdDAPBgNVHRMBAf8EBTADAQH/MB8G\n" +
            "A1UdIwQYMBaAFNSuk5EY8MsHAKr7hYgWlF7vvWIzMBEGA1UdIAQKMAgwBgYEVR0g\n" +
            "ADAdBgNVHQ4EFgQU1K6TkRjwywcAqvuFiBaUXu+9YjMwDgYDVR0PAQH/BAQDAgGG\n" +
            "MA0GCSqGSIb3DQEBCwUAA4ICAQDZZN0oD9kIZ3puvGAcxwGKZ1DNCNtnNut5k4E+\n" +
            "hBJc5TnMskfyM2drMi0vFvFXXJlu5NBprS0jw+x6XHYTC6BXwe4LwZib/Yr/6ROv\n" +
            "73nC/ecJK2w2n6PIWehs7qwigakzh1tf8iypj8kTl2taMMEgzO7bF9CgLQnm0eVj\n" +
            "uPzvRRSsZ0dbBisKwkOTpt9aYG/WsuLZ7LmFKBvpVSvJJBYmgGmeqkx0Pijdg9PE\n" +
            "kUP3Ek2tN5DoOFQzlPicujZ5p3akfTG4L2PNuZWf52zmY5sXmxEr0zoyeuXrIM42\n" +
            "4c5qvh82yvP2M2AXty8s2O1jW11snemSLPVhxsnUlfMqic8rfO0QTPJg3WU/SmHp\n" +
            "vmcyzUGpwYfm1wdOS2e9Ow5fSxR6TyHc14Lox4yXCLzGkPdBPcj8jG1qJ9Pqkwpa\n" +
            "z9hGC3elTd3TDCocDRlrz6OQfE4j1OKCeaiuHCjZO3v3e0VxWh7T9Synez/thxi/\n" +
            "UPKBL8Gh103AUCOQYGJkIdIKSyQusnfxCj93YE5cJUC9rPfrqe1Rjct3nGNj5E5w\n" +
            "nVwU4HtvosPw6mGtPuUNA3fhvntZN+P+1hi9+322s1s0ttdBYjIYNKVRqiuGB8NH\n" +
            "4xX8R6husmmRbOI1OFdtaruc30rSo1Y3/iYWdWaA1zokkYOztcjbffoznZlIBawm\n" +
            "if4oKw==\n" +
            "-----END CERTIFICATE-----\n" +
            "\n" +
            "\n" +
            "*******************************************\n" +
            "*******************************************";

    private static final String responseWithChain = "Keystore type: jks\n" +
            "Keystore provider: SUN\n" +
            "\n" +
            "Your keystore contains 2 entries\n" +
            "\n" +
            "Alias name: cacert\n" +
            "Creation date: May 10, 2021\n" +
            "Entry type: trustedCertEntry\n" +
            "\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFcDCCA1igAwIBAgIUQ8qEcLshApVCEh1+wrszGBW9mHEwDQYJKoZIhvcNAQEL\n" +
            "BQAwNjEWMBQGA1UEAwwNTWFuYWdlbWVudCBDQTEcMBoGA1UECgwTM0tleSBDb21w\n" +
            "YW55IHMuci5vLjAeFw0xOTA1MDgxMjUxNTZaFw0yOTA1MDUxMjUxNTZaMDYxFjAU\n" +
            "BgNVBAMMDU1hbmFnZW1lbnQgQ0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIu\n" +
            "by4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDZ3+k1GPIGkimNd9ME\n" +
            "w9cWCYYzUh11mv5NVJsw+uRbzxQsP7oqeQQdMxHqhSP0eGg6UxqQ6PQSCCkHvMtr\n" +
            "pFGX+eMZuB/z1vFodHdBCUTNOUr6c0c+wMGuhJoYPAwY/OW5YDrw6r1oxtKbbD7H\n" +
            "MOPE1tt5twGQTuy4BBQEWp/SSHs39UoDtLqbLwzuekv1GcQxCjWpHjX5fIbIf7JZ\n" +
            "fXrQ8WnMkHInbow9tQIAOtKyDJ32Y2DUSgK4v1zp0UtnABXBaVyih3am/Sghv6RL\n" +
            "jP0xEnWpRtAt4HqtSFFMVCEkgqIEU7Ev9eTuGJvy76lvvrPpr5dow35FWz8tZcPw\n" +
            "PwXKMqaHRPPIjS3HDKi/BOmqOGpnANcJyn4X+/NsOTNkIXLAj9H5t4deQR4jckSw\n" +
            "NcPeh/5zXgqmPU5GLhhis+zu0TxfMKuEovXHOWlfiyU4Xzx6MAsjb9dPRqjR2ku7\n" +
            "TNc9megR7yDV809eOa6M5roVZB2L71/rKKkzLS/u9kImShhtqlxQ9XckN0Op2Gpp\n" +
            "PYIO8rzmZHzCv+gb/NIeVZ+UbTIbANA3NYXWjJlMzgyf/Dub0vZbhRxLpKRcziOZ\n" +
            "N8STB8p+d6kChct1u10SZwQglMUM8WPo8t+CHPw/AvApdwD2z45CktFiR6V83gqv\n" +
            "qGdDkaCg/CdpnzltHN/Zr4NDpwIDAQABo3YwdDAPBgNVHRMBAf8EBTADAQH/MB8G\n" +
            "A1UdIwQYMBaAFNSuk5EY8MsHAKr7hYgWlF7vvWIzMBEGA1UdIAQKMAgwBgYEVR0g\n" +
            "ADAdBgNVHQ4EFgQU1K6TkRjwywcAqvuFiBaUXu+9YjMwDgYDVR0PAQH/BAQDAgGG\n" +
            "MA0GCSqGSIb3DQEBCwUAA4ICAQDZZN0oD9kIZ3puvGAcxwGKZ1DNCNtnNut5k4E+\n" +
            "hBJc5TnMskfyM2drMi0vFvFXXJlu5NBprS0jw+x6XHYTC6BXwe4LwZib/Yr/6ROv\n" +
            "73nC/ecJK2w2n6PIWehs7qwigakzh1tf8iypj8kTl2taMMEgzO7bF9CgLQnm0eVj\n" +
            "uPzvRRSsZ0dbBisKwkOTpt9aYG/WsuLZ7LmFKBvpVSvJJBYmgGmeqkx0Pijdg9PE\n" +
            "kUP3Ek2tN5DoOFQzlPicujZ5p3akfTG4L2PNuZWf52zmY5sXmxEr0zoyeuXrIM42\n" +
            "4c5qvh82yvP2M2AXty8s2O1jW11snemSLPVhxsnUlfMqic8rfO0QTPJg3WU/SmHp\n" +
            "vmcyzUGpwYfm1wdOS2e9Ow5fSxR6TyHc14Lox4yXCLzGkPdBPcj8jG1qJ9Pqkwpa\n" +
            "z9hGC3elTd3TDCocDRlrz6OQfE4j1OKCeaiuHCjZO3v3e0VxWh7T9Synez/thxi/\n" +
            "UPKBL8Gh103AUCOQYGJkIdIKSyQusnfxCj93YE5cJUC9rPfrqe1Rjct3nGNj5E5w\n" +
            "nVwU4HtvosPw6mGtPuUNA3fhvntZN+P+1hi9+322s1s0ttdBYjIYNKVRqiuGB8NH\n" +
            "4xX8R6husmmRbOI1OFdtaruc30rSo1Y3/iYWdWaA1zokkYOztcjbffoznZlIBawm\n" +
            "if4oKw==\n" +
            "-----END CERTIFICATE-----\n" +
            "\n" +
            "\n" +
            "*******************************************\n" +
            "*******************************************\n" +
            "\n" +
            "\n" +
            "Alias name: lab01.3key.company\n" +
            "Creation date: May 10, 2021\n" +
            "Entry type: PrivateKeyEntry\n" +
            "Certificate chain length: 2\n" +
            "Certificate[1]:\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIElTCCAn2gAwIBAgIUJUklMtjmXOXa3im4mB044JbEKNQwDQYJKoZIhvcNAQEL\n" +
            "BQAwNjEWMBQGA1UEAwwNTWFuYWdlbWVudCBDQTEcMBoGA1UECgwTM0tleSBDb21w\n" +
            "YW55IHMuci5vLjAeFw0yMTA1MTAwNzE3MDZaFw0yMzA1MTAwNzE3MDVaMDsxGzAZ\n" +
            "BgNVBAMMEmxhYjAxLjNrZXkuY29tcGFueTEcMBoGA1UECgwTM0tleSBDb21wYW55\n" +
            "IHMuci5vLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKYiVyZW23V+\n" +
            "BP59/RQ+EM5MpDVJwNg1q0zUmLoItUKHNYLBGNVYGOdDQA5eEkZ905oeZIaQJ7g7\n" +
            "6N2yMrzDgSdlriAccWkK2OTRqube9v/G+185TgkYUhzR9vS/izZR5yWh8rDxt81K\n" +
            "0iKmpG6HV3P9PbNcoYVQIIbzdYTd/JfGr8rLCRMULdAWJXyLJaZ7oQNk/LsHvzFx\n" +
            "9n6IfrAovSVqDkjn8Hm6nFHtSnAt3VQc9/8eFzNgtTdiPq9AuKLB3GhP5rMsa4p2\n" +
            "BYhyx5Hk3PbFvUKzIje/ExeadHNqJcT7wGHltNTlRXZMiHLASz6oYXgdd6Yo9Sp0\n" +
            "kKCISIPlotMCAwEAAaOBlTCBkjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFNSu\n" +
            "k5EY8MsHAKr7hYgWlF7vvWIzMB0GA1UdEQQWMBSCEmxhYjAxLjNrZXkuY29tcGFu\n" +
            "eTATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUI8knt72/swFL2cNcxBqt\n" +
            "Lm4+UE0wDgYDVR0PAQH/BAQDAgWgMA0GCSqGSIb3DQEBCwUAA4ICAQAOjtMX2XfR\n" +
            "ufScV6BleQgIKL1TZ7iuwNYkXKBBwAgcHBsbuOlc5KGeovfhIFr8l8gIHpZ2fG4+\n" +
            "iaOTw6Y1URUOTUsKcmrRhb75aBRF+GTGRoPGNgKuzUmtUkSr7yZQyMHOpTfDZyLm\n" +
            "a22RRuIHZCQMhd+No9LmzMDHorG8bhPWVObenIjdW//2bF27z0gwQuCV2PrPkJsh\n" +
            "4J1+99RJW0vR0HSF1rpoVQfteXR+1orr0ETRScSLIWYqZpm1sUhJzT+U8GFsin1t\n" +
            "g5Kua0dxCB2I1nzvemZVMPqrj/BgthWdo2z1s9bLEcTJsDy1gfIIQ65PimJsOwjA\n" +
            "qlZa2eTbFBS7LuXcrZdc5/rhvuLR6oyY/sVZ/YuE+2rtWrk9YbpQUlmlu68kUvRy\n" +
            "oI25mLTGgBrWcPBWOxOKaN35inpkvZ+NPgfD+Bwsypwv08KkYlfnyTWvoqqXf5ge\n" +
            "nn6w0bSVeMyOxzs5YfnQnFqvd3AIkSN+1B8bKb+kdUZ+6d4/ipv3Gm5HalxnpSGY\n" +
            "/cQAvuAlF+7iGtpppDfAXh8MbwJonOObxe6wcY14mvZgqSYHZ+ls+9kTanwWSAvB\n" +
            "T6PBT4ZLIs6RjVUSWpcrf4VJ5kgE3ESDpf9h4BYrYus41FpwB6MYIGbN9dvl6P9w\n" +
            "pWGBD4WD+8ffbnGmo10YMp56GTCn5xCwKQ==\n" +
            "-----END CERTIFICATE-----\n" +
            "Certificate[2]:\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFcDCCA1igAwIBAgIUQ8qEcLshApVCEh1+wrszGBW9mHEwDQYJKoZIhvcNAQEL\n" +
            "BQAwNjEWMBQGA1UEAwwNTWFuYWdlbWVudCBDQTEcMBoGA1UECgwTM0tleSBDb21w\n" +
            "YW55IHMuci5vLjAeFw0xOTA1MDgxMjUxNTZaFw0yOTA1MDUxMjUxNTZaMDYxFjAU\n" +
            "BgNVBAMMDU1hbmFnZW1lbnQgQ0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIu\n" +
            "by4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDZ3+k1GPIGkimNd9ME\n" +
            "w9cWCYYzUh11mv5NVJsw+uRbzxQsP7oqeQQdMxHqhSP0eGg6UxqQ6PQSCCkHvMtr\n" +
            "pFGX+eMZuB/z1vFodHdBCUTNOUr6c0c+wMGuhJoYPAwY/OW5YDrw6r1oxtKbbD7H\n" +
            "MOPE1tt5twGQTuy4BBQEWp/SSHs39UoDtLqbLwzuekv1GcQxCjWpHjX5fIbIf7JZ\n" +
            "fXrQ8WnMkHInbow9tQIAOtKyDJ32Y2DUSgK4v1zp0UtnABXBaVyih3am/Sghv6RL\n" +
            "jP0xEnWpRtAt4HqtSFFMVCEkgqIEU7Ev9eTuGJvy76lvvrPpr5dow35FWz8tZcPw\n" +
            "PwXKMqaHRPPIjS3HDKi/BOmqOGpnANcJyn4X+/NsOTNkIXLAj9H5t4deQR4jckSw\n" +
            "NcPeh/5zXgqmPU5GLhhis+zu0TxfMKuEovXHOWlfiyU4Xzx6MAsjb9dPRqjR2ku7\n" +
            "TNc9megR7yDV809eOa6M5roVZB2L71/rKKkzLS/u9kImShhtqlxQ9XckN0Op2Gpp\n" +
            "PYIO8rzmZHzCv+gb/NIeVZ+UbTIbANA3NYXWjJlMzgyf/Dub0vZbhRxLpKRcziOZ\n" +
            "N8STB8p+d6kChct1u10SZwQglMUM8WPo8t+CHPw/AvApdwD2z45CktFiR6V83gqv\n" +
            "qGdDkaCg/CdpnzltHN/Zr4NDpwIDAQABo3YwdDAPBgNVHRMBAf8EBTADAQH/MB8G\n" +
            "A1UdIwQYMBaAFNSuk5EY8MsHAKr7hYgWlF7vvWIzMBEGA1UdIAQKMAgwBgYEVR0g\n" +
            "ADAdBgNVHQ4EFgQU1K6TkRjwywcAqvuFiBaUXu+9YjMwDgYDVR0PAQH/BAQDAgGG\n" +
            "MA0GCSqGSIb3DQEBCwUAA4ICAQDZZN0oD9kIZ3puvGAcxwGKZ1DNCNtnNut5k4E+\n" +
            "hBJc5TnMskfyM2drMi0vFvFXXJlu5NBprS0jw+x6XHYTC6BXwe4LwZib/Yr/6ROv\n" +
            "73nC/ecJK2w2n6PIWehs7qwigakzh1tf8iypj8kTl2taMMEgzO7bF9CgLQnm0eVj\n" +
            "uPzvRRSsZ0dbBisKwkOTpt9aYG/WsuLZ7LmFKBvpVSvJJBYmgGmeqkx0Pijdg9PE\n" +
            "kUP3Ek2tN5DoOFQzlPicujZ5p3akfTG4L2PNuZWf52zmY5sXmxEr0zoyeuXrIM42\n" +
            "4c5qvh82yvP2M2AXty8s2O1jW11snemSLPVhxsnUlfMqic8rfO0QTPJg3WU/SmHp\n" +
            "vmcyzUGpwYfm1wdOS2e9Ow5fSxR6TyHc14Lox4yXCLzGkPdBPcj8jG1qJ9Pqkwpa\n" +
            "z9hGC3elTd3TDCocDRlrz6OQfE4j1OKCeaiuHCjZO3v3e0VxWh7T9Synez/thxi/\n" +
            "UPKBL8Gh103AUCOQYGJkIdIKSyQusnfxCj93YE5cJUC9rPfrqe1Rjct3nGNj5E5w\n" +
            "nVwU4HtvosPw6mGtPuUNA3fhvntZN+P+1hi9+322s1s0ttdBYjIYNKVRqiuGB8NH\n" +
            "4xX8R6husmmRbOI1OFdtaruc30rSo1Y3/iYWdWaA1zokkYOztcjbffoznZlIBawm\n" +
            "if4oKw==\n" +
            "-----END CERTIFICATE-----\n" +
            "\n" +
            "\n" +
            "*******************************************\n" +
            "*******************************************";

    @Test
    public void testCertificateParse() {
        List<KeystoreCertificate> certs = KeystoreResponseUtil.getAllKeystoreCertificates(response);
        Assertions.assertEquals(3, certs.size());
    }

    @Test
    public void testCertificateParseWithChain() {
        List<KeystoreCertificate> certs = KeystoreResponseUtil.getAllKeystoreCertificates(responseWithChain);
        Assertions.assertEquals(3, certs.size());
    }
}

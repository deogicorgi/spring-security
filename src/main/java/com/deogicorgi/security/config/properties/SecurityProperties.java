package com.deogicorgi.security.config.properties;

import lombok.Data;

@Data
public class SecurityProperties {

    private Http http;

    @Data
    public static class Http {
        private FormLogin formLogin;
        private OAuth2Login oAuth2Login;
    }

    @Data
    public static class FormLogin {
        private Url url;
        private Parameter parameter;
    }

    @Data
    public static class OAuth2Login {
        private Url url;
    }

    @Data
    public static class Url {
        private String loginUrl;
        private String processUrl;
        private String logoutUrl;
    }

    @Data
    public static class Parameter {
        private String username;
        private String password;
    }
}

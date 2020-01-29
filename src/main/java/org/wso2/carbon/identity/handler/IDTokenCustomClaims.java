package org.wso2.carbon.identity.handler;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.DefaultOIDCClaimsCallbackHandler;

public class IDTokenCustomClaims extends DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(IDTokenCustomClaims.class);

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthTokenReqMessageContext request) {

        JWTClaimsSet jwtClaimsSet = super.handleCustomClaims(builder, request);
        if (jwtClaimsSet.getClaim("email") != null) {
            builder.claim("http://wso2.org/claims/emailaddress",jwtClaimsSet.getClaim("email"));
        }

        if (jwtClaimsSet.getClaim("groups") != null) {
            builder.claim("http://wso2.org/claims/role",jwtClaimsSet.getClaim("groups"));
        }

        return builder.build();
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext request) {

        JWTClaimsSet jwtClaimsSet = super.handleCustomClaims(builder, request);

        if (jwtClaimsSet.getClaim("email") != null) {
            builder.claim("http://wso2.org/claims/emailaddress",jwtClaimsSet.getClaim("email"));
        }

        if (jwtClaimsSet.getClaim("groups") != null) {
            builder.claim("http://wso2.org/claims/role",jwtClaimsSet.getClaim("groups"));
        }

        return builder.build();
    }
}

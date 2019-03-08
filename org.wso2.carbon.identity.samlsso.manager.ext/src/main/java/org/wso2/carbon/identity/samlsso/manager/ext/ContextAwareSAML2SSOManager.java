package org.wso2.carbon.identity.samlsso.manager.ext;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.DefaultSAML2SSOManager;

/**
 * this is used to override the default behavior of DefaultSAML2SSOManager.
 * add the following to repository/conf/identity/application-authentication.xml
 * 
 * <AuthenticatorConfig name="SAMLSSOAuthenticator" enabled="true">
 *		<Parameter name="SAML2SSOManager">org.wso2.carbon.identity.application.authenticator.samlsso.ext.ContextAwareSAML2SSOManager</Parameter>
 * </AuthenticatorConfig>
 *
 */
public class ContextAwareSAML2SSOManager extends DefaultSAML2SSOManager {

	private static Log log = LogFactory.getLog(ContextAwareSAML2SSOManager.class);

	/**
	 * use this method to override any of the parameters in the SAML request. AuthnRequest =
	 * super.buildAuthnRequest(request, isPassive, idpUrl, context);
	 * 
	 * this method is invoked before signing the SAML request - so changing anything in the SAML
	 * request will not break anything!
	 */
	@Override
	protected AuthnRequest buildAuthnRequest(HttpServletRequest request, boolean isPassive, String idpUrl,
			AuthenticationContext context) throws SAMLSSOException {
		return super.buildAuthnRequest(request, isPassive, idpUrl, context);
	}

	/**
	 * this method is invoked twice during the out-bound login flow. first, while generating the
	 * SAML request to create the issuer element - and then while validating the audience in the
	 * SAML response.
	 */
	@Override
	protected String getIssuer(AuthenticationContext context) {
		String issuer = null;
		String spContext = context.getSequenceConfig().getApplicationConfig().getServiceProvider().getDescription();
		String spName = context.getSequenceConfig().getApplicationConfig().getServiceProvider().getApplicationName();

		try {
			if (spContext != null && !spContext.isEmpty()) {
				JSONObject json = new JSONObject(spContext);
				issuer = (String) json.get("issuer");
			}
		} catch (JSONException e) {
			// no valid json message provided
			log.error("Error occurred pasring the JSON payload set as description for the service provider " + spName);
		}

		if (issuer == null) {
			return super.getIssuer(context);
		}

		return issuer;
	}
}
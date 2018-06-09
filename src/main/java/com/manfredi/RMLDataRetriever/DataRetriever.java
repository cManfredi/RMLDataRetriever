package com.manfredi.RMLDataRetriever;

import java.io.IOException;

import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;

public final class DataRetriever {
	
	public static boolean checkAuth(String userId, IDataSource ds) throws IOException{
		//Only checks if the user has a token stored in the DataStore for the passed DataSource
		return ds.checkAuth(userId);
	}
	
	public static String getAuthRequest(String userId, IDataSource ds, String authCallback) throws IOException{
		return ds.buildAuthRequest(userId, authCallback);
	}
//	
//	public void saveAuthResponse(String userId, DataSource ds, HttpServletRequest request) throws IOException, TokenResponseException{
//		AuthorizationCodeFlow flow = this.getAuthCodeFlow(ds);
//		String code = request.getParameter("code");
//		TokenResponse resp = flow.newTokenRequest(code).setRedirectUri(request.getRequestURL().toString()).execute();
//		flow.createAndStoreCredential(resp, userId);
//	}
//	
//	public void updateData(String userId, DataSource ds, long lastUpdate) throws IOException{
//		AuthorizationCodeFlow flow = this.getAuthCodeFlow(ds);
//		Credential credentials = flow.loadCredential(userId);
//		//Making request for profile information
//		HttpRequestFactory factory = this.httpTransport.createRequestFactory(credentials);
//		//TODO per ogni risorsa da richiedere, creare una richiesta e poi salvare il risultato
////		HttpResponse resp = factory.buildGetRequest(new GenericUrl("https://api.fitbit.com/1/user/-/profile.json")).execute();
//	}
//	
//	//TODO modifica con i DataSoure per rendere il metodo modulare rispetto alle differenti sorgenti di dati
//	private AuthorizationCodeFlow getAuthCodeFlow(DataSource ds) throws IOException {
//		AuthorizationCodeFlow flow = null;
//		flow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
//		    this.httpTransport,
//		    this.jsonFactory,
//		    new GenericUrl(ds.getTokenUrl()),
//		    new BasicAuthentication(ds.getClientId(), ds.getClientSecret()),
//		    ds.getClientId(),
//		    ds.getAuthUrl())
//		.setDataStoreFactory(this.dataStoreFactory)
//		.setScopes(ds.getScopes())
//		.build();
//		return flow;
//	}
}

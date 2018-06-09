package com.manfredi.RMLDataRetriever;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.configuration2.BaseHierarchicalConfiguration;
import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Base64;
import com.google.api.client.util.StringUtils;
import com.google.api.client.util.store.DataStore;
import com.google.api.client.util.store.FileDataStoreFactory;

public class NokiaHealthDataSource implements IDataSource {
	
	private DataStore<String> dataStore = null;
	private HttpRequestFactory reqFactory = null;
	
	/** Secure random number generator to sign requests. */
	private static final SecureRandom RANDOM = new SecureRandom();
	
	/**
	 * Client_Id and Client_Secret of the app registration
	 */
	private static final String CONSUMER_KEY = "6450c1698b0fd392ff0cd3f607f4ed90f0cfe9f4e2360bb41c7913fe7917b";
	private static final String CONSUMER_SECRET = "d05e59c201bc7cc03ed1556824ff541bf45d645b6c77ecf2f6c12be658d5";
	
	/** Temporary token Url */
	private static final String REQUEST_TOKEN_URL = "https://developer.health.nokia.com/account/request_token";
	
	/** Authorization Url */
	private static final String AUTHORIZE_URL = "https://developer.health.nokia.com/account/authorize";
	
	/** OAuth Url */
	private static final String ACCESS_TOKEN_URL = "https://developer.health.nokia.com/account/access_token";
	
	/** Request data Url */
	private static final String REQUEST_DATA_URL = "https://api.health.nokia.com/v2/measure";
	
	/** Prefix */
	private static final String PREFIX = "nokia-health";
	
	/**
	 * Scope e Risorse vengono caricati tramite file di configurazione XML alla creazione dell'istanza.
	 * Gli scope vengono utilizzati in fase di autorizzazione mentre le risorse per il recupero dei dati.
	 */
	private List<String> scopes;
	private HashMap<String, WebResource> resources;
	
	/**
	 * Percorso del file di configurazione per Scope e Risorse.
	 */
	private static final java.io.File CONFIG_FILE =
		      new java.io.File(System.getProperty("user.home"), "DataRetriever/config/" + PREFIX + ".xml");
	
	private static final java.io.File CREDENTIAL_STORE_DIR =
		      new java.io.File(System.getProperty("user.home"), ".store/data_retriever/" + PREFIX);
	
	private static final java.io.File DATA_STORE_DIR =
		      new java.io.File(System.getProperty("user.home"), "DataRetriever/" + PREFIX + "-data");
	
	public NokiaHealthDataSource() throws IOException, ConfigurationException{
		log("Init resources");
		this.initResources();
		//Usiamo uno store di semplici stringhe
		log("Init data store");
		this.dataStore = new FileDataStoreFactory(CREDENTIAL_STORE_DIR).getDataStore("NokiaHealthStore");
		log("Init request factory");
		this.reqFactory = new NetHttpTransport().createRequestFactory();
	}

	@Override
	public boolean checkAuth(String userId) throws IOException {
		log("checking auth with id: "+ PREFIX + "-" + userId + "-token");
		return this.dataStore.get(PREFIX + "-" + userId + "-token") != null;
	}

	@Override
	public String buildAuthRequest(String userId, String authCallback) throws IOException {
		log("BUILD AUTH REQUEST");
		String urlToReturn = null;
		log("creating tokenParamsBuilder");
		String tokenParams = generateParamsString(authCallback, null, null);
		log("generating signature for baseString: "+ generateBaseString(REQUEST_TOKEN_URL, tokenParams));
		String signToken = computeSignature(generateBaseString(REQUEST_TOKEN_URL, tokenParams), null);
		log("adding signature: " + signToken);
		//Aggiungo la firma
		tokenParams = generateParamsString(authCallback, null, signToken);
		// Eseguo la richiesta
		log("executing request");
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(REQUEST_TOKEN_URL + "?" + tokenParams)).execute();
		String content = response.parseAsString();
		log("extracting content - null? " + (content == null));
		//Recupero i token dalla risposta
		if(content != ""){
			String[] vals = content.split("&", 2);
			String token = "";
			String tokenSecret = "";
			for (int i = 0; i < vals.length; i++) {
				String[] parts = vals[i].split("=", 2);
				if(i == 0){
					token = parts[1];
				} else {
					tokenSecret = parts[1];
				}
			}
			log("TEMPORARY token: " + token + " - tokenSecret: " + tokenSecret);
			// Devo salvare token e tokenSecret, da sostituire poi con quelli definitivi
			log("saving temporary tokens");
			this.dataStore.set(PREFIX + "-" + userId + "-token-temp", token);
			this.dataStore.set(PREFIX + "-" + userId + "-tokenSecret-temp", tokenSecret);
			log("Building auth redirect url");
			// Creo la richiesta per reindirizzare l'utente, stavolta includendo tra i parametri anche il token ottenuto
			String authParams = generateParamsString(null, token, null);
			// Aggiungo la firma, questa volta uso anche il nuovo segreto per firmare
			log("generating signature for baseString: "+ generateBaseString(AUTHORIZE_URL, authParams));
			String signAuth = computeSignature(generateBaseString(AUTHORIZE_URL, authParams), tokenSecret);
			log("adding signature: " + signAuth);
			authParams = generateParamsString(null, token, signAuth);
			urlToReturn = this.reqFactory.buildGetRequest(new GenericUrl(AUTHORIZE_URL + "?" + authParams)).getUrl().build();
			log("returning url: " + urlToReturn);
		} else {
			return null;
		}
		return urlToReturn;
	}

	@Override
	public void saveAuthResponse(String userId, HashMap<String, String> params) throws IOException {
		log("SAVE AUTH RESPONSE");
		// Salvo nel DataStore lo userId Nokia dell'utente
		this.dataStore.set(PREFIX + "-" + userId + "-userId", params.get("userid"));
		log("got nokia id: "+ params.get("userid"));
		//Recupero il token temporaneo
		String token = this.dataStore.get(PREFIX + "-" + userId + "-token-temp");
		log("temporary token: " + token);
		//Recupero il tokenSecret temporaneo
		String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret-temp");
		log("temporary token secret: " + tokenSecret);
		// Creo la richiesta per ottenere l'access token e il secret access token
		String tokenParams = generateParamsString(null, token, null);
		log("generating signature for baseString: "+ generateBaseString(ACCESS_TOKEN_URL, tokenParams));
		// Aggiungo la firma, questa volta uso anche il nuovo segreto per firmare
		String signAuth = computeSignature(generateBaseString(ACCESS_TOKEN_URL, tokenParams), tokenSecret);
		log("adding signature: " + signAuth);
		tokenParams = generateParamsString(null, token, signAuth);
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(ACCESS_TOKEN_URL + "?" + tokenParams)).execute();
		String content = response.parseAsString();
		log("extracting content - null? " + (content == null));
		//Recupero i token definitivi dalla risposta
		if(content != ""){
			String[] vals = content.split("&", 4);
			token = "";
			tokenSecret = "";
			for (int i = 0; i < 2; i++) {
				String[] parts = vals[i].split("=", 2);
				if(i == 0){
					token = parts[1];
				} else {
					tokenSecret = parts[1];
				}
			}
			// Devo salvare token e tokenSecret definitivi
			this.dataStore.set(PREFIX + "-" + userId + "-token", token);
			this.dataStore.set(PREFIX + "-" + userId + "-tokenSecret", tokenSecret);
			this.dataStore.delete(PREFIX + "-" + userId + "-token-temp");
			this.dataStore.delete(PREFIX + "-" + userId + "-tokenSecret-temp");
			log("DEFINITIVE token: " + token + " - tokenSecret: " + tokenSecret);
		}
	}

	@Override
	public String updateData(String userId, String resourceName, long lastUpdate) throws IOException {
		log("UPDATE SINGLE RESOURCE");
		// resourceName deve essere una delle stringhe definite nel file di configurazione, altrimenti non accade nulla
		WebResource res = this.resources.get(resourceName);
		if(res != null){
			//Recupero userId Nokia Health
			String nokiaId = this.dataStore.get(PREFIX + "-" + userId + "-userId");
			log("nokia id: "+nokiaId);
			//Recupero token e tokenSecret
			String token = this.dataStore.get(PREFIX + "-" + userId + "-token");
			String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret");
			log("token: "+token+" - tokenSecret: "+tokenSecret);
			// Invio la richiesta
			if(nokiaId != null && token != null && tokenSecret != null){
				// Viene restituito il percorso del file appena creato in modo che possa essere subito elaborato
				return getAndSave(res, token, tokenSecret, nokiaId, lastUpdate);
			} else {
				return null;
			}
		} else {
			return null;
		}
	}

	@Override
	public String[] updateAllData(String userId, long lastUpdate) throws IOException {
		log("UPDATE ALL RESOURCES");
		// In questo caso viene effettuata una richiesta per ogni risorsa configurata e vengono restituiti i percorsi a tutti i file
		// creati
		ArrayList<String> paths = new ArrayList<String>();
		//Recupero userId Nokia Health
		String nokiaId = this.dataStore.get(PREFIX + "-" + userId + "-userId");
		log("nokia id: "+nokiaId);
		//Recupero token e tokenSecret
		String token = this.dataStore.get(PREFIX + "-" + userId + "-token");
		String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret");
		log("token: "+token+" - tokenSecret: "+tokenSecret);
		// Invio la richiesta
		if(nokiaId != null && token != null && tokenSecret != null){
			// Si invia una richiesta per ogni risorsa
			for(WebResource resource : this.resources.values()){
				paths.add(getAndSave(resource, token, tokenSecret, nokiaId, lastUpdate));
			}
			return (String[]) paths.toArray();
		} else {
			return null;
		}
	}
	
	private String generateNonce() {
		log("generating nonce");
		return Long.toHexString(Math.abs(RANDOM.nextLong()));
	}
	
	private String generateTimestamp(){
		log("generating timestamp");
		return Long.toString(System.currentTimeMillis() / 1000);
	}
	
	private String generateParamsString(String authCallback, String token, String signature) throws UnsupportedEncodingException{
		// Creazione stringa parametri, parametri in ordine alfabetico
		TreeMap<String, String> params = new TreeMap<>();
		if(authCallback != null){	
			params.put("oauth_callback", URLEncoder.encode(authCallback, "UTF-8"));
		}
		params.put("oauth_consumer_key", CONSUMER_KEY);
		params.put("oauth_nonce", generateNonce());
		if(signature != null){
			params.put("oauth_signature", URLEncoder.encode(signature, "UTF-8"));
		}
		params.put("oauth_signature_method", "HMAC-SHA1");
		params.put("oauth_timestamp", generateTimestamp());
		if(token != null){
			params.put("oauth_token", token);
		}
		params.put("oauth_version", "1.0");
		// Concatenazione
		StringBuilder paramsBuilder = new StringBuilder();
		boolean first = true;
		for(Map.Entry<String, String> param : params.entrySet()){
			if(first){
				first = false;
			} else {
				paramsBuilder.append("&");
			}
			paramsBuilder.append(param.getKey()).append("=").append(param.getValue());
		}
		return paramsBuilder.toString();
	}
	
	private String generateBaseString(String url, String paramsString) throws UnsupportedEncodingException{
		String baseString = null;
		// Creazione baseString
		StringBuilder buffer = new StringBuilder();
		// Metodo richiesta
		buffer.append("GET");
		// URL
		buffer.append("&").append(URLEncoder.encode(url, "UTF-8"));
		// Parametri
		buffer.append("&").append(URLEncoder.encode(paramsString, "UTF-8"));
		baseString = buffer.toString();
		return baseString;
	}
	
	private String computeSignature(String baseString, String tokenSecret){
		String signature = null;
		// Costruisco il segreto da utilizzare
		StringBuilder secret = new StringBuilder();
		secret.append(CONSUMER_SECRET).append("&");
		if(tokenSecret != null){
			secret.append(tokenSecret);
		}
		// Creo la chiave segreta
		SecretKeySpec secretKey = new SecretKeySpec(secret.toString().getBytes(), "HmacSHA1");
	    Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA1");
			mac.init(secretKey);
			signature = URLEncoder.encode(Base64.encodeBase64String(mac.doFinal(baseString.getBytes())), "UTF-8");
		} catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signature;
	}
	
	/**
	 * Metodo per leggere da file gli Scopes e le risorse di interesse per il servizio Nokia Health
	 * @throws ConfigurationException 
	 */
	private void initResources() throws ConfigurationException{
		// Consultare la guida online per Apache Common Configurations
		Configurations configs = new Configurations();
	    XMLConfiguration config = configs.xml(CONFIG_FILE.getAbsolutePath());
	    //Scopes
	    this.scopes = config.getList(String.class, "scopes.scope");
	    //Risorse
	    HashMap<String, WebResource> resources = new HashMap<>();
	    List fields = config.configurationsAt("resources.resource");
	    for(Iterator i = fields.iterator(); i.hasNext();){
	    	BaseHierarchicalConfiguration bhc = (BaseHierarchicalConfiguration) i.next();
	    	resources.put(
    			bhc.getString("name"), 
    			new WebResource(bhc.getString("fileNameToFormat"), bhc.getString("pathToFormat"))
			);
	    }
	    this.resources = resources;
	}
	
	private String getAndSave(WebResource res, String token, String tokenSecret, String nokiaId, long lu) throws IOException{
		log("GET AND SAVE");
		// Formatto la risorsa specificando la data se richiesta, alcune richiesta prevedono che venga specificato il periodo d'interesse
		int lastUpdate = (int) (lu / 1000L);
		log("last update: "+lastUpdate);
		// Richiedo i dati fino ad ora
		int now = (int) (System.currentTimeMillis() / 1000L);
		log("now: "+now);
		// Non ho bisogno di formattare le date in quanto accetta i timestamp
		// Path della risorsa online
		String path = String.format(res.getResourcePathToFormat(), nokiaId, lastUpdate, now);
		log("path: "+path);
		// Nome del file per il salvataggio in locale - prevede sempre e solo che venga specificato il timestamp attuale
		String fileName = String.format(res.getResourceFileName(), now);
		log("filename: "+fileName);
		// Creo la richiesta per ottenere l'access token e il secret access token
		String tokenParams = generateParamsString(null, token, null);
		log("generating signature for baseString: "+ generateBaseString(REQUEST_DATA_URL,path + "&" +  tokenParams));
		// Aggiungo la firma, questa volta uso anche il nuovo segreto per firmare
		String signAuth = computeSignature(generateBaseString(REQUEST_DATA_URL, path + "&" + tokenParams), tokenSecret);
		log("adding signature: "+signAuth);
		tokenParams = generateParamsString(null, token, signAuth);
		log("Url:" + REQUEST_DATA_URL + "?" + path + "&" + tokenParams);
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(REQUEST_DATA_URL + "?" + path + "&" + tokenParams)).execute();
		String content = response.parseAsString();
		log("extracting content: "+content);
		
		// Se non ci sono errori salvo il file CSV in un file nella cartella specificata
		
		//Check sulla cartella di salvataggio
		if(!DATA_STORE_DIR.isDirectory()){
			DATA_STORE_DIR.mkdirs();
		}
		//Creo il file
		java.io.File file = new java.io.File(DATA_STORE_DIR.getAbsolutePath(), fileName);
		FileOutputStream fos = new FileOutputStream(file);
		//Recupero il contenuto della risposta, un CSV
		InputStream is = response.getContent();
		log("Starting reading the content and saving on file");
		//Scrivo su file
		int read = 0;
		byte[] buffer = new byte[32768];
		while( (read = is.read(buffer)) > 0) {
		  fos.write(buffer, 0, read);
		}
		// Chiudo gli stream
		fos.close();
		is.close();
		// Restituisco il percorso al file appena creato
		return file.getAbsolutePath();
	}
	
	private static void log(String msg){
		System.out.println("[LOG Nokia] : " + msg);
	}
	
}

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
	
	/** Secure random number generator needed to sign requests. */
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
	 * Scopes and Resources are loaded via XML configuration file when an instance is created.
	 * Scopes are used to request authorization to the provider while Resources hold informations used when making 
	 * requests.
	 */
	private List<String> scopes;
	private HashMap<String, WebResource> resources;
	
	/**
	 * XML configuration file path.
	 */
	private static final java.io.File CONFIG_FILE =
		      new java.io.File(System.getProperty("user.home"), "RMLDataRetriever/config/" + PREFIX + ".xml");
	
	/**
	 * Path of the File Data Store to save OAuth credentials.
	 */
	private java.io.File CREDENTIAL_STORE_DIR;
	
	/**
	 * Path of the directory where all the retrieved data is saved.
	 */
	private java.io.File DATA_STORE_DIR;
	
	public NokiaHealthDataSource() throws IOException, ConfigurationException{
		log("Init resources");
		// Init from config file
		this.initResources();
		//The data store contains simple strings
		log("Init data store");
		this.dataStore = new FileDataStoreFactory(CREDENTIAL_STORE_DIR).getDataStore("NokiaHealthStore");
		log("Init request factory");
		// Factory used to build HTTP requests
		this.reqFactory = new NetHttpTransport().createRequestFactory();
	}

	@Override
	public boolean checkAuth(String userId) throws IOException {
		log("checking auth with id: "+ PREFIX + "-" + userId + "-token");
		// Check if a token is already stored for this user
		return this.dataStore.get(PREFIX + "-" + userId + "-token") != null;
	}

	@Override
	public String buildAuthRequest(String userId, String authCallback) throws IOException {
		log("BUILD AUTH REQUEST");
		String urlToReturn = null;
		log("creating tokenParamsBuilder");
		// Get parameters string without signature
		String tokenParams = generateParamsString(authCallback, null, null);
		log("generating signature for baseString: "+ generateBaseString(REQUEST_TOKEN_URL, tokenParams));
		// Generate the signature based on the parameters in the request
		String signToken = computeSignature(generateBaseString(REQUEST_TOKEN_URL, tokenParams), null);
		log("adding signature: " + signToken);
		// Add the signature to the list of parameters
		tokenParams = generateParamsString(authCallback, null, signToken);
		// Execute the request
		log("executing request");
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(REQUEST_TOKEN_URL + "?" + tokenParams)).execute();
		// Extract the response as a String to verify it is not empty
		String content = response.parseAsString();
		log("extracting content - null? " + (content == null));
		if(content != ""){
			// Get the tokens from the response
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
			// Save the temporary tokens in the data store, to be replaced with definitive ones
			log("saving temporary tokens");
			this.dataStore.set(PREFIX + "-" + userId + "-token-temp", token);
			this.dataStore.set(PREFIX + "-" + userId + "-tokenSecret-temp", tokenSecret);
			log("Building auth redirect url");
			// Build request to redirect user on the service provider site
			String authParams = generateParamsString(null, token, null);
			// Build signature, this time using also the temporary secret token received
			log("generating signature for baseString: "+ generateBaseString(AUTHORIZE_URL, authParams));
			String signAuth = computeSignature(generateBaseString(AUTHORIZE_URL, authParams), tokenSecret);
			// Add signature to parameters
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
		// Save the userId of the Nokia service, received with the request
		this.dataStore.set(PREFIX + "-" + userId + "-userId", params.get("userid"));
		log("got nokia id: "+ params.get("userid"));
		// Get temporary token from data store
		String token = this.dataStore.get(PREFIX + "-" + userId + "-token-temp");
		log("temporary token: " + token);
		// Get temporary secret token from data store
		String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret-temp");
		log("temporary token secret: " + tokenSecret);
		// Build request to get definitive tokens
		String tokenParams = generateParamsString(null, token, null);
		log("generating signature for baseString: "+ generateBaseString(ACCESS_TOKEN_URL, tokenParams));
		// Compute signature
		String signAuth = computeSignature(generateBaseString(ACCESS_TOKEN_URL, tokenParams), tokenSecret);
		log("adding signature: " + signAuth);
		// Add signature to parameters
		tokenParams = generateParamsString(null, token, signAuth);
		// As before, parse response to save definitive tokens
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(ACCESS_TOKEN_URL + "?" + tokenParams)).execute();
		String content = response.parseAsString();
		log("extracting content - null? " + (content == null));
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
			// Save definitive tokens and delete temporary ones
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
		// resourceName, since resources are loaded from config file, has to match the resource name of the config
		WebResource res = this.resources.get(resourceName);
		if(res != null){
			// Get nokiaID, token and secret token from data store
			String nokiaId = this.dataStore.get(PREFIX + "-" + userId + "-userId");
			log("nokia id: "+nokiaId);
			String token = this.dataStore.get(PREFIX + "-" + userId + "-token");
			String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret");
			log("token: "+token+" - tokenSecret: "+tokenSecret);
			if(nokiaId != null && token != null && tokenSecret != null){
				// In case the file with the retrieved data is successfully created the path is returned, otherwise null
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
		// One request for each Resource
		ArrayList<String> paths = new ArrayList<String>();
		// Get nokiaID, token and secret token from data store
		String nokiaId = this.dataStore.get(PREFIX + "-" + userId + "-userId");
		log("nokia id: "+nokiaId);
		String token = this.dataStore.get(PREFIX + "-" + userId + "-token");
		String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret");
		log("token: "+token+" - tokenSecret: "+tokenSecret);
		if(nokiaId != null && token != null && tokenSecret != null){
			// As before
			for(WebResource resource : this.resources.values()){
				paths.add(getAndSave(resource, token, tokenSecret, nokiaId, lastUpdate));
			}
			// Returns array of paths
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
		// Building parameters string, alphabetically ordered, as requested by Nokia Health API
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
		// Generating base string, made of HTTP method, URL and parameters
		StringBuilder buffer = new StringBuilder();
		// HTTP Method
		buffer.append("GET");
		// URL
		buffer.append("&").append(URLEncoder.encode(url, "UTF-8"));
		// Parameters
		buffer.append("&").append(URLEncoder.encode(paramsString, "UTF-8"));
		baseString = buffer.toString();
		return baseString;
	}
	
	private String computeSignature(String baseString, String tokenSecret){
		String signature = null;
		// Building secret used to sign, can be only the client secret or client secret + token secret
		StringBuilder secret = new StringBuilder();
		secret.append(CONSUMER_SECRET).append("&");
		if(tokenSecret != null){
			secret.append(tokenSecret);
		}
		// Build secret key for HMAC-SHA1 algorithm
		SecretKeySpec secretKey = new SecretKeySpec(secret.toString().getBytes(), "HmacSHA1");
	    Mac mac;
		try {
			// Compute signature
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
	 * Init method - config is stored in an XML file
	 * @throws ConfigurationException 
	 */
	private void initResources() throws ConfigurationException{
		// Read online user guide for Apache Common Configurations
		Configurations configs = new Configurations();
		XMLConfiguration config = configs.xml(CONFIG_FILE.getAbsolutePath());
	    // Credential store dir
	    this.CREDENTIAL_STORE_DIR = new java.io.File(config.getString("credentialStoreDir"));
	    // Data store dir
	    this.DATA_STORE_DIR = new java.io.File(config.getString("dataStoreDir"));
	    //Scopes
	    this.scopes = config.getList(String.class, "scopes.scope");
	    //Resources
	    HashMap<String, WebResource> resources = new HashMap<>();
	    List fields = config.configurationsAt("resources.resource");
	    for(Iterator i = fields.iterator(); i.hasNext();){
	    	BaseHierarchicalConfiguration bhc = (BaseHierarchicalConfiguration) i.next();
	    	// Resources are stored in an HashMap using name as key and WebResource instance as value
	    	resources.put(
    			bhc.getString("name"), 
    			new WebResource(bhc.getString("fileNameToFormat"), bhc.getString("pathToFormat"))
			);
	    }
	    this.resources = resources;
	}
	
	private String getAndSave(WebResource res, String token, String tokenSecret, String nokiaId, long lu) throws IOException{
		log("GET AND SAVE");
		// Format request url parameters to specify, if needed, the last update timestamp
		int lastUpdate = (int) (lu / 1000L);
		log("last update: "+lastUpdate);
		// Timestamp of current execution
		int now = (int) (System.currentTimeMillis() / 1000L);
		log("now: "+now);
		// Online resource URI, got from config file and formatted with parameters
		String path = String.format(res.getResourcePathToFormat(), nokiaId, lastUpdate);
		log("path: "+path);
		// File name of the file where data will be saved, encoded with timestamp of creation
		String fileName = String.format(res.getResourceFileName(), now);
		log("filename: "+fileName);
		// Building request with the usual process
		String tokenParams = generateParamsString(null, token, null);
		log("generating signature for baseString: "+ generateBaseString(REQUEST_DATA_URL,path + "&" +  tokenParams));
		// Adding the computed signature
		String signReq = computeSignature(generateBaseString(REQUEST_DATA_URL, path + "&" + tokenParams), tokenSecret);
		log("adding signature: "+signReq);
		tokenParams = generateParamsString(null, token, signReq);
		log("Url:" + REQUEST_DATA_URL + "?" + path + "&" + tokenParams);
		// Execute request
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(REQUEST_DATA_URL + "?" + path + "&" + tokenParams)).execute();
		// Checking content
		String content = response.parseAsString();
		log("extracting content: "+content);
		
		// If there are no errors, saving data to JSON file
		
		// Check on directory
		if(!DATA_STORE_DIR.isDirectory()){
			DATA_STORE_DIR.mkdirs();
		}
		// Creating file reference
		java.io.File file = new java.io.File(DATA_STORE_DIR.getAbsolutePath(), fileName);
		// Output stream
		FileOutputStream fos = new FileOutputStream(file);
		// Content of response in JSON
		InputStream is = response.getContent();
		log("Starting reading the content and saving on file");
		// Writing on file
		int read = 0;
		byte[] buffer = new byte[32768];
		while( (read = is.read(buffer)) > 0) {
		  fos.write(buffer, 0, read);
		}
		// Closing streams
		fos.close();
		is.close();
		// Returning path to written file
		return file.getAbsolutePath();
	}
	
	private static void log(String msg){
		System.out.println("[LOG Nokia] : " + msg);
	}
	
}

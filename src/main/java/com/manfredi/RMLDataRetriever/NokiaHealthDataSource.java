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
	private static final String REQUEST_DATA_URL = "https://api.health.nokia.com/measure";
	
	/** Prefix */
	private static final String PREFIX = "nokia-health";
	
	/**
	 * Scopes and Resources are loaded via XML configuration file when an instance is created.
	 * Scopes are used to request authorization to the provider while Resources hold informations used when making 
	 * requests.
	 */
//	private List<String> scopes;
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
		// Init from config file
		this.initResources();
		//The data store contains simple strings
		this.dataStore = new FileDataStoreFactory(CREDENTIAL_STORE_DIR).getDataStore("NokiaHealthStore");
		// Factory used to build HTTP requests
		this.reqFactory = new NetHttpTransport().createRequestFactory();
	}

	@Override
	public boolean checkAuth(String userId) throws IOException {
		// Check if a token is already stored for this user
		return this.dataStore.get(PREFIX + "-" + userId + "-token") != null;
	}

	@Override
	public String buildAuthRequest(String userId, String authCallback) throws IOException {
		String urlToReturn = null;
		// Get parameters string without signature
		TreeMap<String, String> paramsTreeToken = getParamsTree();
		paramsTreeToken.put("oauth_callback", URLEncoder.encode(authCallback, "UTF-8"));
		// Generate the signature based on the parameters in the request
		String signToken = computeSignature(generateBaseString(REQUEST_TOKEN_URL, buildTree(paramsTreeToken)), null);
		// Add the signature to the list of parameters
		paramsTreeToken.put("oauth_signature", signToken);
		// Get list of parameters
		String tokenParams = buildTree(paramsTreeToken);
		// Execute the request
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(REQUEST_TOKEN_URL + "?" + tokenParams)).execute();
		// Extract the response as a String to verify it is not empty
		String content = response.parseAsString();
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
			// Save the temporary tokens in the data store, to be replaced with definitive ones
			this.dataStore.set(PREFIX + "-" + userId + "-token-temp", token);
			this.dataStore.set(PREFIX + "-" + userId + "-tokenSecret-temp", tokenSecret);
			// Build request to redirect user on the service provider site
			TreeMap<String, String> paramsTreeAuth = getParamsTree();
			paramsTreeAuth.put("oauth_callback", URLEncoder.encode(authCallback, "UTF-8"));
			paramsTreeAuth.put("oauth_token", token);
			// Build signature, this time using also the temporary secret token received
			String signAuth = computeSignature(generateBaseString(AUTHORIZE_URL, buildTree(paramsTreeAuth)), tokenSecret);
			// Add signature to parameters
			paramsTreeAuth.put("oauth_signature", signAuth);
			urlToReturn = this.reqFactory.buildGetRequest(new GenericUrl(AUTHORIZE_URL + "?" + buildTree(paramsTreeAuth))).getUrl().build();
		} else {
			return null;
		}
		return urlToReturn;
	}

	@Override
	public void saveAuthResponse(String userId, HashMap<String, String> params) throws IOException {
		// Save the userId of the Nokia service, received with the request
		this.dataStore.set(PREFIX + "-" + userId + "-userId", params.get("userid"));
		// Get temporary token from data store
		String token = this.dataStore.get(PREFIX + "-" + userId + "-token-temp");
		// Get temporary secret token from data store
		String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret-temp");
		// Build request to get definitive tokens
		TreeMap<String, String> paramsTree = getParamsTree();
		paramsTree.put("oauth_token", token);
		// Compute signature
		String signAuth = computeSignature(generateBaseString(ACCESS_TOKEN_URL, buildTree(paramsTree)), tokenSecret);
		// Add signature to parameters
		paramsTree.put("oauth_signature", signAuth);
		// As before, parse response to save definitive tokens
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(ACCESS_TOKEN_URL + "?" + buildTree(paramsTree))).execute();
		String content = response.parseAsString();
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
		}
	}

	@Override
	public String updateData(String userId, String resourceName, long lastUpdate) throws IOException {
		// resourceName, since resources are loaded from config file, has to match the resource name of the config
		WebResource res = this.resources.get(resourceName);
		if(res != null){
			// Get nokiaID, token and secret token from data store
			String nokiaId = this.dataStore.get(PREFIX + "-" + userId + "-userId");
			String token = this.dataStore.get(PREFIX + "-" + userId + "-token");
			String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret");
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
		// One request for each Resource
		ArrayList<String> paths = new ArrayList<String>();
		// Get nokiaID, token and secret token from data store
		String nokiaId = this.dataStore.get(PREFIX + "-" + userId + "-userId");
		String token = this.dataStore.get(PREFIX + "-" + userId + "-token");
		String tokenSecret = this.dataStore.get(PREFIX + "-" + userId + "-tokenSecret");
		if(nokiaId != null && token != null && tokenSecret != null){
			// As before
			for(WebResource resource : this.resources.values()){
				paths.add(getAndSave(resource, token, tokenSecret, nokiaId, lastUpdate));
			}
			// Returns array of paths
			String[] toReturn = new String[paths.size()];
			toReturn = paths.toArray(toReturn);
			return toReturn;
		} else {
			return null;
		}
	}
	
	private String generateNonce() {
		return Long.toHexString(Math.abs(RANDOM.nextLong()));
	}
	
	private String generateTimestamp(){
		return Long.toString(System.currentTimeMillis() / 1000);
	}
	
	private String buildTree(TreeMap<String, String> map){
		StringBuilder paramsBuilder = new StringBuilder();
		boolean first = true;
		for(Map.Entry<String, String> param : map.entrySet()){
			if(first){
				first = false;
			} else {
				paramsBuilder.append("&");
			}
			paramsBuilder.append(param.getKey()).append("=").append(param.getValue());
		}
		return paramsBuilder.toString();
	}
	
	private TreeMap<String, String> getParamsTree() throws UnsupportedEncodingException{
		// Building parameters string, alphabetically ordered, as requested by Nokia Health API
		TreeMap<String, String> params = new TreeMap<>();
		params.put("oauth_consumer_key", CONSUMER_KEY);
		params.put("oauth_nonce", generateNonce());
		params.put("oauth_signature_method", "HMAC-SHA1");
		params.put("oauth_timestamp", generateTimestamp());
		params.put("oauth_version", "1.0");
		return params;
	}
	
	private String generateBaseString(String url, String params) throws UnsupportedEncodingException{
		String baseString = null;
		// Generating base string, made of HTTP method, URL and parameters
		StringBuilder buffer = new StringBuilder();
		// HTTP Method
		buffer.append("GET");
		// URL
		buffer.append("&").append(URLEncoder.encode(url, "UTF-8"));
		// Parameters
		buffer.append("&").append(URLEncoder.encode(params, "UTF-8"));
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
		// Format request url parameters to specify, if needed, the last update timestamp
		int lastUpdate = (int) (lu / 1000L);
		// Timestamp of current execution
		int now = (int) (System.currentTimeMillis() / 1000L);
		// Online resource URI, got from config file and formatted with parameters
		String path = String.format(res.getResourcePathToFormat(), nokiaId, lastUpdate);
		// File name of the file where data will be saved, encoded with timestamp of creation
		String fileName = String.format(res.getResourceFileName(), now);
		// Building request with the usual process
		TreeMap<String, String> paramsTree = getParamsTree();
		paramsTree.put("oauth_token", token);
		//Adding parameters from path to build Tree to be ordered alphabetically
		String[] pathParams = path.split("&");
		for(String tuple : pathParams){
			String[] parts = tuple.split("=");
			paramsTree.put(parts[0], parts[1]);
		}
		// Adding the computed signature
		String signReq = computeSignature(generateBaseString(REQUEST_DATA_URL, buildTree(paramsTree)), tokenSecret);
		paramsTree.put("oauth_signature", signReq);
		// Execute request
		HttpResponse response = this.reqFactory.buildGetRequest(new GenericUrl(REQUEST_DATA_URL + "?" + buildTree(paramsTree))).execute();
		// Checking content
		
		// saving data to JSON file
		
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
	
}

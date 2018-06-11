package com.manfredi.RMLDataRetriever;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.configuration2.BaseHierarchicalConfiguration;
import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;

public class FitbitDataSource implements IDataSource {
	
	/**
	 * To communicate with Fitbit Web API using OAuth2 protocol, the Google Client Oauth Java library will be used, in
	 * particular the AuthorizationCodeFlow class who manages credentials, build requests and executes them as prescribed
	 * in the Oauth2 protocol.
	 */
	private AuthorizationCodeFlow flow = null;
	
	/**
	 * CLIENT_ID and CLIENT_SECRET obtained when registering RML Data Retriever as a Fitbit app.
	 */
	private static final String CLIENT_ID = "22CS9Q";
	private static final String CLIENT_SECRET = "0a19958ef9828e187b5bfce70ec80538";
	
	/**
	 * URL to request token.
	 */
	private static final String TOKEN_URL = "https://api.fitbit.com/oauth2/token";
	
	/**
	 * URL to redirect user on the service provider site for authorization.
	 */
	private static final String AUTH_URL = "https://api.fitbit.com/oauth2/authorize";
	
	/**
	 * Prefix for data related to this class.
	 */
	private static final String PREFIX = "fitbit";
	
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
	
	/**
	 * In the constructor scopes and resources are initialized and the AuthorizationCodeFlow instance is created with the
	 * right data.
	 * @throws IOException
	 * @throws ConfigurationException
	 */
	public FitbitDataSource() throws IOException, ConfigurationException{
		// Init
		this.initResources();
		// Creating AuthorizationCodeFlow
		this.flow = new AuthorizationCodeFlow.Builder(
			BearerToken.authorizationHeaderAccessMethod(),
		    new NetHttpTransport(),
		    new JacksonFactory(),
		    new GenericUrl(TOKEN_URL),
		    new BasicAuthentication(CLIENT_ID, CLIENT_SECRET),
		    CLIENT_ID,
		    AUTH_URL)
		// storing credentials on a file
		.setDataStoreFactory(new FileDataStoreFactory(CREDENTIAL_STORE_DIR))
		.setScopes(this.scopes)
		.build();
	}

	public boolean checkAuth(String userId) throws IOException {
		Credential cred = this.flow.loadCredential(PREFIX + "-" + userId);
		return cred != null;
	}

	public String buildAuthRequest(String userId, String authCallback) throws IOException {
		// Returns the Url to redirect the user on the service provider site
		return this.flow.newAuthorizationUrl().setRedirectUri(authCallback).build();
	}

	public void saveAuthResponse(String userId, HashMap<String, String> params) throws IOException {
		// Getting the authorization code from the request
		String code = params.get("code");
		// Requesting the access token - without redirect Uri the API returns an error
		TokenResponse response = 
				this.flow.newTokenRequest(code)
				.setRedirectUri("http://localhost:8080/RMLDataRetriever/AuthCallback")
				.execute();
		// Saving token in credential data store
		this.flow.createAndStoreCredential(response, PREFIX + "-" + userId);
	}

	public String updateData(String userId, String resourceName, long lastUpdate) throws IOException {
		// resourceName must be a string used to define the name of a resource in the XML config file
		WebResource res = this.resources.get(resourceName);
		if(res != null){
			// Loading credentials
			Credential credentials = this.flow.loadCredential(PREFIX + "-" + userId);
			if(credentials != null){
				// Building request factory with credentials
				HttpRequestFactory factory = this.flow.getTransport().createRequestFactory(credentials);
				// In case the file with the retrieved data is successfully created the path is returned, otherwise null
				return getAndSave(factory, res, lastUpdate);
			} else {
				return null;
			}
		} else {
			return null;
		}
	}

	public String[] updateAllData(String userId, long lastUpdate) throws IOException {
		// One request for each Resource - see comments on updateData
		ArrayList<String> paths = new ArrayList<String>();
		Credential credentials = this.flow.loadCredential(PREFIX + "-" + userId);
		if(credentials != null){
			HttpRequestFactory factory = this.flow.getTransport().createRequestFactory(credentials);
			for(WebResource resource : this.resources.values()){
				paths.add(getAndSave(factory, resource, lastUpdate));
			}
			return (String[]) paths.toArray();
		} else {
			return null;
		}
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
	    	resources.put(bhc.getString("name"), new WebResource(bhc.getString("fileNameToFormat"), bhc.getString("pathToFormat")));
	    }
	    this.resources = resources;
	}
	
	private String getAndSave(HttpRequestFactory factory, WebResource res, long lastUpdate) throws IOException{
		// Format request url parameters to specify, if needed, when it was last updated
		Date lastUpdateDate = new Date(lastUpdate);
		// Date of current execution
		Date now = new Date();
		// Formatting dates to be accepted by service provider
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
		// Online resource URI, got from config file and formatted with parameters
		String path = String.format(res.getResourcePathToFormat(), formatter.format(lastUpdateDate), formatter.format(now));
		// File name of the file where data will be saved, encoded with timestamp of creation
		String fileName = String.format(res.getResourceFileName(), now.getTime() / 1000);
		// Building and executing request
		HttpResponse response = factory.buildGetRequest(new GenericUrl("https://api.fitbit.com/1/user/-/" + path + ".json")).execute();
		
		// If there are no errors, saving data to JSON file
		
		// Check on directory
		if(!DATA_STORE_DIR.isDirectory()){
			DATA_STORE_DIR.mkdirs();
		}
		// Creating file reference
		java.io.File file = new java.io.File(DATA_STORE_DIR.getAbsolutePath(), fileName);
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

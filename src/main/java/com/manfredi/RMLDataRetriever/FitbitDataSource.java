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
	 * Per la comunicazione con le Web API di Fitbit, mediante protocollo OAuth2, viene utilizzata la libreria Google Client
	 * OAuth Java ed, in particolare, la classe AuthorizationCodeFlow che si occupa della gestione delle credenziali, della
	 * creazione ed esecuzione delle richieste HTTP, ecc...
	 */
	private AuthorizationCodeFlow flow = null;
	
	/**
	 * CLIENT_ID e CLIENT_SECRET ottenuti al momento della registrazione dell'applicazione presso Fitbit - DA SOSTITUIRE.
	 */
	private static final String CLIENT_ID = "22CS9Q";
	private static final String CLIENT_SECRET = "0a19958ef9828e187b5bfce70ec80538";
	
	/**
	 * URL per la richiesta dei token.
	 */
	private static final String TOKEN_URL = "https://api.fitbit.com/oauth2/token";
	
	/**
	 * URL per la richiesta dell'autorizzazione - l'utente viene reindirizzato presso questo indirizzo.
	 */
	private static final String AUTH_URL = "https://api.fitbit.com/oauth2/authorize";
	
	/**
	 * Prefisso utilizzato per la creazione di file e per il salvataggio delle credenziali.
	 */
	private static final String PREFIX = "fitbit";
	
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
	
	/**
	 * Percorso per il salvataggio delle credenziali OAuth.
	 */
	private static final java.io.File CREDENTIAL_STORE_DIR =
		      new java.io.File(System.getProperty("user.home"), ".store/data_retriever/" + PREFIX);
	
	/**
	 * Percorso per il salvataggio dei dati recuperati da remoto.
	 */
	private static final java.io.File DATA_STORE_DIR =
		      new java.io.File(System.getProperty("user.home"), "DataRetriever/" + PREFIX + "-data");
	
	/**
	 * All'interno del costruttore vengono inizializzati Scope e Risorse e successivamente creata l'istanza di AuthorizationCodeFlow
	 * con i parametri necessari.
	 * @throws IOException
	 * @throws ConfigurationException
	 */
	public FitbitDataSource() throws IOException, ConfigurationException{
		// Inizializzazione da file mediante Apache Common Configurations
		this.initResources();
		// Creazione AuthorizationCodeFlow
		this.flow = new AuthorizationCodeFlow.Builder(
			BearerToken.authorizationHeaderAccessMethod(),
		    new NetHttpTransport(),
		    new JacksonFactory(),
		    new GenericUrl(TOKEN_URL),
		    new BasicAuthentication(CLIENT_ID, CLIENT_SECRET),
		    CLIENT_ID,
		    AUTH_URL)
		// Viene utilizzato il salvataggio delle credenziali su file
		.setDataStoreFactory(new FileDataStoreFactory(CREDENTIAL_STORE_DIR))
		// E' necessario definire gli Scope utilizzati
		.setScopes(this.scopes)
		.build();
	}

	public boolean checkAuth(String userId) throws IOException {
		Credential cred = this.flow.loadCredential(PREFIX + "-" + userId);
		return cred != null;
	}

	public String buildAuthRequest(String userId, String authCallback) throws IOException {
		// Ritorna l'URL per reindirizzare l'utente alla pagina di autorizzazione presso il provider
		return this.flow.newAuthorizationUrl().setRedirectUri(authCallback).build();
	}

	public void saveAuthResponse(String userId, HashMap<String, String> params) throws IOException {
		// Fitbit prevede il passaggio di un parametro GET contenente un codice da utilizzare nella richiesta per Access Token
		String code = params.get("code");
		// Viene impostato l'URI di redirezione anche in questa richiesta solo perch� richiesto dal provider, altrimenti restituisce
		// un errore
		TokenResponse response = 
				this.flow.newTokenRequest(code)
				.setRedirectUri("http://localhost:8080/RMLDataRetriever/AuthCallback")
				.execute();
		// Una volta ottenuto il token in risposta vengono salvate le credenziali
		this.flow.createAndStoreCredential(response, PREFIX + "-" + userId);
	}

	public String updateData(String userId, String resourceName, long lastUpdate) throws IOException {
		// resourceName deve essere una delle stringhe definite nel file di configurazione, altrimenti non accade nulla
		WebResource res = this.resources.get(resourceName);
		if(res != null){
			// Caricamento delle credenziali salvate, updateData non dovrebbe essere chiamato se le credenziali non sono presenti
			Credential credentials = this.flow.loadCredential(PREFIX + "-" + userId);
			if(credentials != null){
				// Invio della richiesta per la risorsa di interesse
				HttpRequestFactory factory = this.flow.getTransport().createRequestFactory(credentials);
				// Viene restituito il percorso del file appena creato in modo che possa essere subito elaborato
				return getAndSave(factory, res, lastUpdate);
			} else {
				return null;
			}
		} else {
			return null;
		}
	}

	public String[] updateAllData(String userId, long lastUpdate) throws IOException {
		// In questo caso viene effettuata una richiesta per ogni risorsa configurata e vengono restituiti i percorsi a tutti i file
		// creati
		ArrayList<String> paths = new ArrayList<String>();
		Credential credentials = this.flow.loadCredential(PREFIX + "-" + userId);
		if(credentials != null){
			HttpRequestFactory factory = this.flow.getTransport().createRequestFactory(credentials);
			// Si invia una richiesta per ogni risorsa
			for(WebResource resource : this.resources.values()){
				paths.add(getAndSave(factory, resource, lastUpdate));
			}
			return (String[]) paths.toArray();
		} else {
			return null;
		}
	}
	
	/**
	 * Metodo per leggere da file gli Scopes e le risorse di interesse per il servizio fitbit
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
	    	resources.put(bhc.getString("name"), new WebResource(bhc.getString("fileNameToFormat"), bhc.getString("pathToFormat")));
	    }
	    this.resources = resources;
	}
	
	private String getAndSave(HttpRequestFactory factory, WebResource res, long lastUpdate) throws IOException{
		// Formatto la risorsa specificando la data se richiesta, alcune richiesta prevedono che venga specificato il periodo d'interesse
		Date lastUpdateDate = new Date(lastUpdate);
		// Richiedo i dati fino ad ora
		Date now = new Date();
		// Formatto le date in modo che vengano accettate dal provider
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
		// Path della risorsa online
		String path = String.format(res.getResourcePathToFormat(), formatter.format(lastUpdateDate), formatter.format(now));
		// Nome del file per il salvataggio in locale - prevede sempre e solo che venga specificato il timestamp attuale
		String fileName = String.format(res.getResourceFileName(), now.getTime() / 1000);
		// Invio la richiesta e recupero la risposta
		HttpResponse response = factory.buildGetRequest(new GenericUrl("https://api.fitbit.com/1/user/-/" + path + ".json")).execute();
		
		// Se non ci sono errori salvo il JSON in un file nella cartella specificata
		
		//Check sulla cartella di salvataggio
		if(!DATA_STORE_DIR.isDirectory()){
			DATA_STORE_DIR.mkdirs();
		}
		//Creo il file
		java.io.File file = new java.io.File(DATA_STORE_DIR.getAbsolutePath(), fileName);
		FileOutputStream fos = new FileOutputStream(file);
		//Recupero il contenuto della risposta, un JSON
		InputStream is = response.getContent();
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
	
}

package com.manfredi.RMLDataRetriever;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

/**
 * Interfaccia che ogni classe che rappresenta un servizio online per il recupero di dati deve implementare.
 * L'effettiva implementazione del meccanismo di autenticazione e recupero dei dati, essendo specifico di ogni servizio,
 * viene delegato alla classe che implementa questa interfaccia.
 * @author cmanf
 *
 */
public interface IDataSource {
	
	/**
	 * Metodo per controllare se all'interno della banca dati delle credenziali di questo servizio è presente una voce relativa 
	 * all'utente in questione
	 * @param userId
	 * @return Valore true se le credenziali vengono trovate e sono, quindi, già memorizzate
	 * @throws IOException
	 */
	abstract public boolean checkAuth(String userId) throws IOException;
	
	/**
	 * Metodo per ottenere il link di redirezione necessario a portare l'utente sulla pagina del provider del servizio affinché
	 * autorizzi il software a recuperare i dati dalle Web API. Il metodo restituisce un URL.
	 * 
	 * @param userId
	 * @param authCallback URL di callback passato al metodo deve essere lo stesso che è stato registrato quando si è richiesta la 
	 * chiave ed il segreto per utilizzare le API.
	 * @return
	 * @throws IOException
	 */
	abstract public String buildAuthRequest(String userId, String authCallback) throws IOException;
	
	/**
	 * Una volta che l'utente autorizza l'applicazione il provider reindirizza l'utente mediante l'URL di callback passato nella
	 * richiesta. A questo punto è necessario chiamare questo metodo per salvare le credenziali ottenute all'interno della banca
	 * dati.
	 * @param userId
	 * @param params Parametri della richiesta ricevuta dal provider, ogni servizio implementa il recupero del parametro di
	 * interesse, è necessario solo inserire tutti i parametri GET in un HashMap.
	 * @throws IOException
	 */
	abstract public void saveAuthResponse(String userId, HashMap<String, String> params) throws IOException;
	
	/**
	 * Metodo per richiedere l'aggiornamento di una singola risorsa presso un servizio.
	 * @param userId
	 * @param name nome della risorsa, utilizzato nel file di configurazione come parametro "name" della risorsa
	 * @param lastUpdate per eseguire una richiesta incrementale e non richiedere anche i dati già recuperati
	 * @return
	 * @throws IOException
	 */
	abstract public String updateData(String userId, String resourceName, long lastUpdate) throws IOException;
	
	/**
	 * Metodo per aggiornare tutte le risorse di un determinato servizio.
	 * @param userId
	 * @param lastUpdate per eseguire una richiesta incrementale e non richiedere anche i dati già recuperati
	 * @return
	 * @throws IOException
	 */
	abstract public String[] updateAllData(String userId, long lastUpdate) throws IOException;
	
}

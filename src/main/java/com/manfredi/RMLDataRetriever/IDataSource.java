package com.manfredi.RMLDataRetriever;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

/**
 * Interface implemented by every service provider class. The actual implementation, different for each provider, 
 * is delegated to the class implementing the interface.
 * @author Christian Manfredi
 *
 */
public interface IDataSource {
	
	/**
	 * Method to check if there are any stored credential in the data store for the user.
	 * @param userId
	 * @return
	 * @throws IOException
	 */
	abstract public boolean checkAuth(String userId) throws IOException;
	
	/**
	 * Method to build the Uri used to redirect the user to the service provider site to give authorization.
	 * @param userId
	 * @param authCallback callback URL used when the app was registered on the service provider site. Some providers require
	 * to specify it with every request.
	 * @return
	 * @throws IOException
	 */
	abstract public String buildAuthRequest(String userId, String authCallback) throws IOException;
	
	/**
	 * Once the user has authorized the application, the provider redirect it on the app using the callback URL. This method 
	 * saves the credentials sent back with the request in the data store.
	 * @param userId
	 * @param params HashMap containing all the parameters of the request
	 * @throws IOException
	 */
	abstract public void saveAuthResponse(String userId, HashMap<String, String> params) throws IOException;
	
	/**
	 * Updates data of a single resource
	 * @param userId
	 * @param name resource name as in the XML config file
	 * @param lastUpdate
	 * @return
	 * @throws IOException
	 */
	abstract public String updateData(String userId, String resourceName, long lastUpdate) throws IOException;
	
	/**
	 * Updates data of all resources
	 * @param userId
	 * @param lastUpdate
	 * @return
	 * @throws IOException
	 */
	abstract public String[] updateAllData(String userId, long lastUpdate) throws IOException;
	
}

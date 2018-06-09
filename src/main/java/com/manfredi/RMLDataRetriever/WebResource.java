package com.manfredi.RMLDataRetriever;

public class WebResource {
	
	private String resourceFileName;
	private String resourcePathToFormat;
	
	public WebResource(String name, String path){
		this.resourceFileName = name;
		this.resourcePathToFormat = path;
	}

	/**
	 * @return the resourceFileName
	 */
	public String getResourceFileName() {
		return resourceFileName;
	}

	/**
	 * @param resourceFileName the resourceFileName to set
	 */
	public void setResourceFileName(String resourceName) {
		this.resourceFileName = resourceName;
	}

	/**
	 * @return the resourcePathToFormat
	 */
	public String getResourcePathToFormat() {
		return resourcePathToFormat;
	}

	/**
	 * @param resourcePathToFormat the resourcePathToFormat to set
	 */
	public void setResourcePathToFormat(String resourcePathToFormat) {
		this.resourcePathToFormat = resourcePathToFormat;
	}
}

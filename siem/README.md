# Threat Intelligence Feeds (TI Feeds) by ANY.RUN  

 

TI Feeds help MSSPs and SOCs fortify their security with filtered, high-fidelity indicators of compromise (IPs, domains, URLs) enriched with context from ANY.RUN’s Interactive Sandbox.  

 

Sourced from real-time sandbox investigations of active attacks across 15,000+
organizations, TI Feeds integrate seamlessly with SIEMs/XDRs/firewalls and other
security solutions to monitor and identify malware and phishing threats.  

 

ANY.RUN’s feeds are updated in real time, allowing you to track threats as they
emerge, develop, and spread to take critical security actions early.  

 

* Unique data: Fresh indicators from live detonations of attacks with links to sandbox sessions with full threat context, including TTPs. 

* No false alerts: TI Feeds provide reliable IOCs with a near-zero false positive rate thanks to pre-processing. 

* Prioritization of incidents: SOC teams use TI Feeds as part of alert triage, incident response, and proactive hunting to effectively handle urgent threats.  

 

TI Feeds are available for integration using STIX/TAXII connectors, as well as API and SDK.  

For more details, feel free to [contact us](https://app.any.run/contact-us/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=fortisiem&utm_content=linktocontactus).  

 

# How to Integrate TI Feeds with FortiSIEM  

 

## 1. Open FortiSIEM and go to the Resources tab. 

 

![img.png](static/img.png) 

 

## 2. In this tab, you can configure the connector to receive URLs, IPs, and domains. We will use the example of URLs. 

 

Open Malware URLs dropdown menu and select ANY.RUN’s connector — **ANY.RUN Malware URL**. 

 

![img_1.png](static/img_1.png) 

 

 

## 3. Click **More** and then **Update** in the menu above.  

 

![img_2.png](static/img_2.png) 

 

 

## 4. Select **Update via API** and click the Edit icon. 

 

![img_4.png](static/img_4.png) 

 

 

## 5. Fill in the following fields:  

* **URL**: Insert https://any.run.  

* **Password**: Paste the authorization token for ANY.RUN’s TI Feeds (without the "Basic" prefix).  

If you don’t have these credentials, contact your account manager at ANY.RUN or fill out [this form](https://any.run/demo/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=fortisiem&utm_content=linktodemo).  

* **Plugin Type**: Select the type of the connector type—Python. 

* **Plugin Name**: Select the connector’s script using dropdown menu: anyrun_threatfeed.py. 

* **Data Update**: Select data update algorithm—Full.  

 

Click Save.  

 

![img_5.png](static/img_5.png) 

 

 

## 6. Configure the connector scheduler by clicking the **Add** button.  

 

![img_6.png](static/img_6.png) 

 

 

## 7. Setup the Schedule. Recommended options to choose:  

 

* **Recurrence Pattern**: Hourly 

* Every 2 hour(s) 

* **Recurrence Range**: No end date  

 

Save changes.  

 

![img_7.png](static/img_7.png) 

 

 

## 8. To view the executing status of the connector, click **Malware URLs**, then **Last Result**. 

 

![img_9.png](static/img_9.png) 

 

 

## Note 

Upon scheduling the connector for the first time, you might see an error message
indicating that you’ve entered a wrong authorization token. In this case, re-enter the
token and relaunch the connector.  

![img_8.png](static/img_8.png) 


If you have any questions, contact us via [this form](https://app.any.run/contact-us/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=fortisiem&utm_content=linktocontactus) or write to [support@any.run](mailto:support@any.run) 
 
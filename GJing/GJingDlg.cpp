// GJingDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "GJing.h"
#include "GJingDlg.h"
#include<windows.h>
#include<cstdio>
#include<cstring>
#include  <afxpriv.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

void exchange(char * a,CString b)
{   int i;int l=b.GetLength();
	memset(a,0,sizeof(a));

USES_CONVERSION;
 char * d=T2A(b);
 strcpy(a,(char *)d);

}

typedef unsigned long long ULL;
const ULL eightf=0xffffffff;
const ULL twelvef=0xffffffffffff;
const ULL CBC_I=0x123456789ABCDEF0;
const ULL CFB_I=0x123456789ABCDEF0;
unsigned char plain[1024];
unsigned char cipher[1024];
unsigned char sk[1024];


int DES_S[8][4][16]={
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,},
    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},

    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},

    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},

    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},

    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},

    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},

    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},

    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

int DES_P[32]={
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

int DES_IP[]={
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

int DES_NIP[]={
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

ULL E(int A){
	int s[8];
	for(int i=0;i<8;i++){
		s[i]=A>>(28-4*i)&(0xF);
	}
	ULL m=0;
	for(int i=0;i<8;i++){
		m<<=1;
		m+=s[(i+7)%8]%2;
		m<<=4;
		m+=s[i];
		m<<=1;
		m+=s[(i+1)%8]>>3;
	}
	return m;
}

int S(int i,int B){
	int j=0,k=0;
	j+=(B>>5)%2;
	j<<=1;
	j+=B%2;
	k=(B>>1)&0xF;
	return DES_S[i][j][k];
}

int P(int a){
	int str1[33];
	for(int i=0;i<32;i++){
		str1[31-i]=a%2;
		a/=2;
	}
	for(int i=0;i<32;i++){
		a*=2;
		a+=str1[DES_P[i]-1];
	}
	return a;
}

int F(int A,ULL J){
	ULL EA=E(A)^J;
	int B[8],C[8];
	int s=0;
	for(int i=0;i<8;i++){
		B[7-i]=EA&0x3F;
		EA>>=6;
		C[7-i]=S(7-i,B[7-i]);
	}
	for(int i=0;i<8;i++){
		s<<=4;
		s=s&0xFFFFFFF0;
		s+=C[i];
	}
	return P(s);
}

void IP(ULL &x,int *ip){
    int tmp[64];
    for(int i=0;i<64;++i){
        tmp[i]=x&1;
        x>>=1;
    }
    for(int i=0;i<64;++i){
        x<<=1;
        x+=tmp[ip[i]-1];
    }
}

void zh_IP(ULL &x){
    IP(x,DES_IP);
}

void ni_IP(ULL &x){
    IP(x,DES_NIP);
}

ULL DES(ULL x,ULL Key,bool flag){
    ULL ANS;
	zh_IP(x);
	int L,R,temp=0;
	if(!flag){
        R=x&eightf;
        L=x>>32;
	}else{
        L=x&eightf;
        R=x>>32;
	}
	ULL K[16];
	for(int i=15;i>=0;i--){
		K[i]=Key&twelvef;
        Key=(Key<<60)|(Key>>4);//循环右移4位
	}//求密钥
	if(!flag){
        for(int i=0;i<16;i++){
            temp=L;
            L=R;
            R=temp^F(R,K[i]);
        }//Feistel型密码的循环
        ANS=R;
        ANS=(ANS<<32)|(L&eightf);
	}else{
        for(int i=15;i>=0;i--){
            temp=R;
            R=L;
            L=temp^F(L,K[i]);
        }
        ANS=L;
        ANS=(ANS<<32)|(R&eightf);
    }
	ni_IP(ANS);
	return ANS;
}

ULL E_DES(ULL x,ULL Key){
    return DES(x,Key,0);
}

ULL D_DES(ULL x,ULL Key){
    return DES(x,Key,1);
}

///////////////////////////////////////////////////////////
//CBC工作模式
///////////////////////////////////////////////////////////

void E_CBC(const char *plain_file,const char *cipher_file,ULL k){

    char mid1[256];
	char mid2[256];
	strcpy(mid1,plain_file);
	strcpy(mid2,cipher_file);
	for(int i=0;i<strlen(mid1);i++)if(mid1[i]=='\\')mid1[i]=='/';
    for(int i=0;i<strlen(mid2);i++)if(mid2[i]=='\\')mid2[i]=='/';


    FILE *fp=fopen(mid1,"rb");
    FILE *fc=fopen(mid2,"wb");

    memset(plain,0,sizeof(plain));
    memset(cipher,0,sizeof(cipher));
    ULL b,c,pc,tmp,bit;
    int i,n,j,m,p,len;
    pc=CBC_I;

	if(fp==NULL)MessageBox(NULL,_T("File Open error"),_T("警告"),MB_OK);
  
    FILETIME start;
	FILETIME end;
    int bytes=0;
	
	GetSystemTimeAsFileTime(&start);
    while(len=fread(plain,sizeof(unsigned char),8,fp)){
        b=0;
		bytes+=8;
        for(j=0;j<len;++j){
            b<<=8;
            b+=plain[j];
        }
        if(j<8){
            b<<=8*(8-j);
        }
        c=E_DES(b^pc,k);
        pc=c;
        tmp=c;
        for(m=7;m>=0;--m){
            bit=tmp&0xff;
            cipher[m]=bit;
            tmp>>=8;
        }
        fwrite(cipher,sizeof(unsigned char),8,fc);
    }
    GetSystemTimeAsFileTime(&end);
    fclose(fp);
    fclose(fc);
    MessageBox(NULL,_T("CBC模式加密完成"),_T(""),MB_OK);
    if(end.dwLowDateTime-start.dwLowDateTime!=0)
	{
		ULL myspeed=bytes;
		int speed=(myspeed*10000000)/(end.dwLowDateTime-start.dwLowDateTime);
		CString str;
		str.Format(_T("%d"),speed);
         str+=_T("bytes/sec");
		MessageBox(NULL,str,_T("加密速度为"),MB_OK);
	}

}

void D_CBC(const char *plain_file,const char *cipher_file,ULL k){

	char mid1[256];
	char mid2[256];
	strcpy(mid1,plain_file);
	strcpy(mid2,cipher_file);
	for(int i=0;i<strlen(mid1);i++)if(mid1[i]=='\\')mid1[i]=='/';
    for(int i=0;i<strlen(mid2);i++)if(mid2[i]=='\\')mid2[i]=='/';

    FILE *fp=fopen(mid1,"rb");
    FILE *fc=fopen(mid2,"wb");

    memset(plain,0,sizeof(plain));
    memset(cipher,0,sizeof(cipher));
    ULL b,c,tmp,pc,bit;
    int i,n,j,m,len;
    pc=CBC_I;

	FILETIME start;
	FILETIME end;
    int bytes=0;
	
	GetSystemTimeAsFileTime(&start);

    if(fp==NULL)MessageBox(NULL,_T("File Open error"),_T("警告"),MB_OK);

    while(len=fread(cipher,sizeof(unsigned char),8,fp)){
        c=0;
		bytes+=8;
        for(j=0;j<8;++j){
            c<<=8;
            c+=cipher[j];
        }
        b=D_DES(c,k)^pc;
        pc=c;
        tmp=b;
        for(m=7;m>=0;--m){
            bit=tmp&0xff;
            plain[m]=bit;
            tmp>>=8;
        }
        fwrite(plain,sizeof(unsigned char),8,fc);
    }
	GetSystemTimeAsFileTime(&end);
    fclose(fp);
    fclose(fc);
    MessageBox(NULL,_T("CBC模式解密完成"),_T(""),MB_OK);
	if(end.dwLowDateTime-start.dwLowDateTime!=0)
	{
		int speed=(bytes*10000000)/(end.dwLowDateTime-start.dwLowDateTime);
		CString str;
		str.Format(_T("%d"),speed);
         str+=_T("bytes/sec");
		MessageBox(NULL,str,_T("加密速度为"),MB_OK);
	}
}

///////////////////////////////////////////////////////////
//CFB工作模式
///////////////////////////////////////////////////////////

void E_CFB(const char *plain_file,const char *cipher_file,ULL k){
 	char mid1[256];
	char mid2[256];
	strcpy(mid1,plain_file);
	strcpy(mid2,cipher_file);
	for(int i=0;i<strlen(mid1);i++)if(mid1[i]=='\\')mid1[i]=='/';
    for(int i=0;i<strlen(mid2);i++)if(mid2[i]=='\\')mid2[i]=='/';

    FILE *fp=fopen(mid1,"rb");
    FILE *fc=fopen(mid2,"wb");

    memset(plain,0,sizeof(plain));
    memset(cipher,0,sizeof(cipher));
    ULL b,c,s,tmp,bit;
    int i,n,j,m,p,len;
    s=CFB_I;

    if(fp==NULL)MessageBox(NULL,_T("File Open error"),_T("警告"),MB_OK);

	
	FILETIME start;
	FILETIME end;
    int bytes=0;
	
	GetSystemTimeAsFileTime(&start);

    while(len=fread(plain,sizeof(unsigned char),8,fp)){
        b=0;
		bytes+=8;
        for(j=0;j<len;++j){
            b<<=8;
            b+=plain[j];
        }
        if(j<8){
            b<<=8*(8-j);
        }
        c=((E_DES(s,k)>>56)<<56)^b;
        s=(s<<8)|(c>>56);
        tmp=c;
        for(m=7;m>=0;--m){
            bit=tmp&0xff;
            cipher[m]=bit;
            tmp>>=8;
        }
        fwrite(cipher,sizeof(unsigned char),8,fc);
    }
	GetSystemTimeAsFileTime(&end);
    fclose(fp);
    fclose(fc);
    MessageBox(NULL,_T("CFB模式加密完成"),_T(""),MB_OK);
    if(end.dwLowDateTime-start.dwLowDateTime!=0)
	{
		int speed=(bytes*10000000)/(end.dwLowDateTime-start.dwLowDateTime);
		CString str;
		str.Format(_T("%d"),speed);
         str+=_T("bytes/sec");
		MessageBox(NULL,str,_T("加密速度为"),MB_OK);
	}
}

void D_CFB(const char *plain_file,const char *cipher_file,ULL k){
 	char mid1[256];
	char mid2[256];
	strcpy(mid1,plain_file);
	strcpy(mid2,cipher_file);
	for(int i=0;i<strlen(mid1);i++)if(mid1[i]=='\\')mid1[i]=='/';
    for(int i=0;i<strlen(mid2);i++)if(mid2[i]=='\\')mid2[i]=='/';

    FILE *fp=fopen(mid1,"rb");
    FILE *fc=fopen(mid2,"wb");
    memset(plain,0,sizeof(plain));
    memset(cipher,0,sizeof(cipher));
    ULL b,c,tmp,s,bit;
    int i,n,j,m,len;
    s=CFB_I;

   if(fp==NULL)MessageBox(NULL,_T("File Open error"),_T("警告"),MB_OK);

   FILETIME start;
	FILETIME end;
    int bytes=0;
	
	GetSystemTimeAsFileTime(&start);

    while(len=fread(cipher,sizeof(unsigned char),8,fp)){
		bytes+=8;
        c=0;
        for(j=0;j<8;++j){
            c<<=8;
            c+=cipher[j];
        }
        b=((E_DES(s,k)>>56)<<56)^c;
        s=(s<<8)|(c>>56);
        tmp=b;
        for(m=7;m>=0;--m){
            bit=tmp&0xff;
            plain[m]=bit;
            tmp>>=8;
        }
        fwrite(plain,sizeof(unsigned char),8,fc);
    }
	GetSystemTimeAsFileTime(&end);
    fclose(fp);
    fclose(fc);
    MessageBox(NULL,_T("CFB模式解密完成"),_T(""),MB_OK);
	if(end.dwLowDateTime-start.dwLowDateTime!=0)
	{
		int speed=(bytes*10000000)/(end.dwLowDateTime-start.dwLowDateTime);
		CString str;
		str.Format(_T("%d"),speed);
         str+=_T("bytes/sec");
		MessageBox(NULL,str,_T("加密速度为"),MB_OK);
	}
}

///////////////////////////////////////////////////////////
//通过短密钥HASH生成DES密钥
///////////////////////////////////////////////////////////

void str_E_DES(unsigned char *plain,ULL k,unsigned char * cbc,unsigned char * cfb){
    int len;
    for(len=0;plain[len];++len);
	char *tfp="d:/tmp1";
	char *tfc="d:/tmp2";
    FILE *fp=fopen(tfp,"wb");
    fwrite(plain,sizeof(unsigned char),len,fp);
    fclose(fp);
    E_CBC(tfp,tfc,k);
	FILE *fc=fopen(tfc,"rb");
    fread(cipher,sizeof(unsigned char),len+7,fc);
	strcpy((char *)cbc,(char *)cipher);
    fclose(fc);
	E_CFB(tfp,tfc,k);
    fc=fopen(tfc,"rb");
    fread(cipher,sizeof(unsigned char),len+7,fc);
    strcpy((char *)cfb,(char *)cipher);
    fclose(fc);
    remove(tfp);
    remove(tfc);
}
ULL HASH_Key(unsigned char *sk){
    int i,j;
    ULL Key=0;
    for(i=0;sk[i];++i){
        j=sk[i]%64;
        Key^=(1<<j);
    }
    return Key;
}
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CGJingDlg 对话框




CGJingDlg::CGJingDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CGJingDlg::IDD, pParent)
{
	    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
		File_in=_T("");
		File_out=_T("");
       
}

void CGJingDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CGJingDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON1, &CGJingDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CGJingDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CGJingDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CGJingDlg::OnBnClickedButton4)
	ON_BN_CLICKED(10006, &CGJingDlg::OnBnClicked10006)
	ON_BN_CLICKED(10007, &CGJingDlg::OnBnClicked10007)
	ON_BN_CLICKED(IDC_BUTTON5, &CGJingDlg::OnBnClickedButton5)
END_MESSAGE_MAP()


// CGJingDlg 消息处理程序

BOOL CGJingDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CGJingDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CGJingDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CGJingDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CGJingDlg::OnBnClickedButton1()
{
	int state1=((CButton *)CGJingDlg::GetDlgItem(10006))->GetCheck();
    int state2=((CButton *)CGJingDlg::GetDlgItem(10007))->GetCheck();
	CGJingDlg::GetDlgItem(10005)->GetWindowTextW(Psd);
	if(!(File_in.Compare(_T(""))))MessageBox(_T("请选择输入文件路径"),_T("警告"),MB_OK);
	else if(!(File_out.Compare(_T(""))))MessageBox(_T("请选择输出文件路径"),_T("警告"),MB_OK);
	else if(!(Psd.Compare(_T(""))))MessageBox(_T("请选择一个合适的短密码"),_T("警告"),MB_OK);
	else if(state1==0&&state2==0)MessageBox(_T("请选择一个工作模式"),_T("警告"),MB_OK);
	else 
	{
        char ch[512];exchange(ch,Psd);
		char in[512];exchange(in,File_in);
		char out[512];exchange(out,File_out);
		ULL k=HASH_Key((unsigned char *)ch);
		if(state1==1)E_CFB(in,out,k);
		else E_CBC(in,out,k);
	}

}

void CGJingDlg::OnBnClickedButton2()
{
	int state1=((CButton *)CGJingDlg::GetDlgItem(10006))->GetCheck();
    int state2=((CButton *)CGJingDlg::GetDlgItem(10007))->GetCheck();
	CGJingDlg::GetDlgItem(10005)->GetWindowTextW(Psd);
	if(!(File_in.Compare(_T(""))))MessageBox(_T("请选择输入文件路径"),_T("警告"),MB_OK);
	else if(!(File_out.Compare(_T(""))))MessageBox(_T("请选择输出文件路径"),_T("警告"),MB_OK);
    else if(!(Psd.Compare(_T(""))))MessageBox(_T("请选择一个合适的短密码"),_T("警告"),MB_OK);
	else if(state1==0&&state2==0)MessageBox(_T("请选择一个工作模式"),_T("警告"),MB_OK);
	else 
	{
        char ch[500];exchange(ch,Psd);
		char in[500];exchange(in,File_in);
		char out[500];exchange(out,File_out);
		ULL k=HASH_Key((unsigned char *)ch);
		if(state1==1)D_CFB(in,out,k);
		else D_CBC(in,out,k);
		
	}
    
}

void CGJingDlg::OnBnClickedButton3()
{
	CFileDialog  dlgFile(TRUE, NULL, NULL, OFN_HIDEREADONLY, _T("|All Files (*.*)|*.*||"), NULL);

    if (dlgFile.DoModal())
    {
        File_in = dlgFile.GetPathName();
    }
	if(File_in.Compare(_T("")))CGJingDlg::GetDlgItem(10001)->SetWindowText(File_in);
}

void CGJingDlg::OnBnClickedButton4()
{
	CFileDialog  dlgFile(FALSE, NULL, NULL, OFN_HIDEREADONLY, _T("|All Files (*.*)|*.*||"), NULL);

    if (dlgFile.DoModal())
    {
        File_out = dlgFile.GetPathName();
    }
	if(File_out.Compare(_T("")))CGJingDlg::GetDlgItem(10002)->SetWindowText(File_out);
}

void CGJingDlg::OnBnClicked10006()
{
	((CButton *)CGJingDlg::GetDlgItem(10006))->SetCheck(true);
	((CButton *)CGJingDlg::GetDlgItem(10007))->SetCheck(false);
}

void CGJingDlg::OnBnClicked10007()
{
	((CButton *)CGJingDlg::GetDlgItem(10006))->SetCheck(false);
	((CButton *)CGJingDlg::GetDlgItem(10007))->SetCheck(true);
}

void CGJingDlg::OnBnClickedButton5()
{
    CString pssd;
	CString text;
    CGJingDlg::GetDlgItem(10008)->GetWindowTextW(text);
	CGJingDlg::GetDlgItem(10009)->GetWindowTextW(pssd);
    char ch[500];exchange(ch,pssd);
	char in[500];exchange(in,text);
    ULL k=HASH_Key((unsigned char *)ch);
	unsigned char cbc[500];
	unsigned char cfb[500];
	CString out1,out2;
	out1.Format(_T("%s"),"");
    out2.Format(_T("%s"),"");
	int uselen;
	uselen=strlen(in);
	if(uselen%8) uselen+=8-uselen%8;
	if(text.Compare(_T("")))
	{
    str_E_DES((unsigned char *)in,k,cbc,cfb);  
	for(int i=0;i<uselen;i++)
	{
		out1.AppendFormat(_T("%02x"),cbc[i]);
	}
    for(int i=0;i<strlen((char *)cfb);i++)
	{
		out2.AppendFormat(_T("%02x"),cfb[i]);
	}
    CGJingDlg::GetDlgItem(10010)->SetWindowTextW(out1);
	CGJingDlg::GetDlgItem(10011)->SetWindowTextW(out2);
	}
}

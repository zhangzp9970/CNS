#include "pch.h"
#include "MyMD5.h"
#include "MySHA256.h"
#include "MyDES.h"
#include "MyAES.h"
#include "MyRSA.h"
#include "MainPage.h"
#include "MainPage.g.cpp"

using namespace std;
using namespace winrt;
using namespace Windows::UI::Xaml;
using namespace Windows::Foundation;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;
using namespace Windows::Storage::Streams;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::UI::Core;
using namespace Windows::System;

namespace winrt::CNS::implementation
{
    MainPage::MainPage()
    {
        InitializeComponent();
    }

    int32_t MainPage::MyProperty()
    {
        throw hresult_not_implemented();
    }

    void MainPage::MyProperty(int32_t /* value */)
    {
        throw hresult_not_implemented();
    }
}


void winrt::CNS::implementation::MainPage::ExchangeButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    if (ButtonState == true)
    {
        ButtonState = false;
        this->LTextBox().Header(winrt::box_value(L"Enter your ciphertext:"));
        this->LTextBox().PlaceholderText(L"Ciphertext");
        this->RTextBox().Header(winrt::box_value(L"Your plaintext:"));
        this->RTextBox().PlaceholderText(L"Plaintext");
        this->ActionButton().Content(winrt::box_value(L"Decrypt"));
    }
    else if (ButtonState == false)
    {
        ButtonState = true;
        this->LTextBox().Header(winrt::box_value(L"Enter your plaintext:"));
        this->LTextBox().PlaceholderText(L"Plaintext");
        this->RTextBox().Header(winrt::box_value(L"Your ciphertext:"));
        this->RTextBox().PlaceholderText(L"Ciphertext");
        this->ActionButton().Content(winrt::box_value(L"Encrypt"));
    }
}

IAsyncAction winrt::CNS::implementation::MainPage::InitRSAAsync()
{
    this->ActionProgressRing().IsActive(true);
    co_await resume_background();
    RSASend.InitRSA();
    RSAReceive.InitRSA();
    co_await resume_foreground(this->InfoBar().Dispatcher());
    this->InfoBar().Severity(muxc::InfoBarSeverity::Informational);
    this->InfoBar().Message(hstring(L"RSA keypair generated!"));
    this->InfoBar().IsOpen(true);
    this->ActionButton().IsEnabled(true);
    this->ActionProgressRing().IsActive(false);
}

IAsyncAction winrt::CNS::implementation::MainPage::EncryptAsync(hstring LText)
{
    this->ActionProgressRing().IsActive(true);
    hstring password = L"";
    if (this->RoS == L"Manual")
    {
        password = SKeyBox().Password();
    }
    co_await resume_background();
    PlainTextSize = LText.size();
    IBuffer buffUtf8Msg = CryptographicBuffer::ConvertStringToBinary(LText, BinaryStringEncoding::Utf8);
    hstring HashText = L"";
    //compute hash
    if (this->MoS == L"MD5")//MD5
    {
        MyMD5 MD5;
        HashText = CryptographicBuffer::EncodeToHexString(MD5.MD5(buffUtf8Msg));
    }
    else//SHA256
    {
        MySHA256 SHA256;
        HashText = CryptographicBuffer::EncodeToHexString(SHA256.SHA256(buffUtf8Msg));
    }
    //sign
    hstring SignedHashText = RSASend.Sign(HashText);
    SignedHashTextSize = SignedHashText.size();
    //concatenate
    hstring TotalText = SignedHashText + LText;
    hstring PlainKey = L"";
    //symmetric encryption
    if (this->DoA == L"DES")//DES
    {
        MyDES DES;
        //generate key
        if (this->RoS == L"Random")
        {
            DES.GenerateSymmetricKey64();
        }
        else
        {
            DES.GenerateSymmetricKey64(password);
        }
        //encrypt
        CypherText = DES.DESCBC(CryptographicBuffer::ConvertStringToBinary(TotalText, BinaryStringEncoding::Utf8), ButtonState);
        PlainKey = DES.Key();
        this->IV = DES.IV();
    }
    else//AES
    {
        MyAES AES;
        //generate key
        if (this->RoS == L"Random")
        {
            AES.GenerateSymmetricKey128();
        }
        else
        {
            AES.GenerateSymmetricKey128(password);
        }
        //encrypt
        CypherText = AES.AESCBC(CryptographicBuffer::ConvertStringToBinary(TotalText, BinaryStringEncoding::Utf8), ButtonState);
        PlainKey = AES.Key();
        this->IV = AES.IV();
    }
    //encrypt key 
    CypherKey = RSAReceive.Encrypt(PlainKey);
    co_await resume_foreground(this->InfoBar().Dispatcher());
    if (this->ToF == L"Text")
    {
        this->RTextBox().Text(CypherText);
    }
    else
    {
        bufferText = CypherText;
    }
    this->RKTextBox().Text(CypherKey);
    ShowInfoBar(muxc::InfoBarSeverity::Success, L"Encrypted!");
    this->ActionProgressRing().IsActive(false);
}

IAsyncAction winrt::CNS::implementation::MainPage::DecryptAsync(hstring LText)
{
    this->ActionProgressRing().IsActive(true);
    CypherKey = this->RKTextBox().Text();
    co_await resume_background();
    //decrypt key
    hstring PlainKey = RSAReceive.Decrypt(CypherKey);
    hstring TotalText = L"";
    //decrypt the message
    if (this->DoA == L"DES")//DES
    {
        MyDES DES;
        DES.Key(PlainKey);
        DES.IV(this->IV);
        TotalText = DES.DESCBC(CryptographicBuffer::DecodeFromHexString(LText), ButtonState);
    }
    else//AES
    {
        MyAES AES;
        AES.Key(PlainKey);
        AES.IV(this->IV);
        TotalText = AES.AESCBC(CryptographicBuffer::DecodeFromHexString(LText), ButtonState);
    }
    hstring SignedHashText = L"";
    hstring PlainText = L"";
    for (uint32_t i = 0; i < SignedHashTextSize; i++)
    {
        SignedHashText = SignedHashText + TotalText[i];
    }
    for (uint32_t i = SignedHashTextSize; i < SignedHashTextSize + PlainTextSize; i++)
    {
        PlainText = PlainText + TotalText[i];
    }
    hstring HashText = L"";
    //decrypt hash value and verify
    if (this->MoS == L"MD5")//MD5
    {
        MyMD5 MD5;
        HashText = CryptographicBuffer::EncodeToHexString(MD5.MD5(CryptographicBuffer::ConvertStringToBinary(PlainText, BinaryStringEncoding::Utf8)));
    }
    else
    {
        MySHA256 SHA256;
        HashText = CryptographicBuffer::EncodeToHexString(SHA256.SHA256(CryptographicBuffer::ConvertStringToBinary(PlainText, BinaryStringEncoding::Utf8)));
    }
    auto verify = RSASend.Verify(SignedHashText, HashText);
    co_await resume_foreground(this->InfoBar().Dispatcher());
    if (verify)
    {
        ShowInfoBar(muxc::InfoBarSeverity::Success, L"Message received correctly!");
    }
    else
    {
        ShowInfoBar(muxc::InfoBarSeverity::Error, L"Message received with errors!");
    }
    if (this->ToF == L"Text")
    {
        this->RTextBox().Text(PlainText);
    }
    else
    {
        bufferText = PlainText;
    }
    this->ActionProgressRing().IsActive(false);
}

void winrt::CNS::implementation::MainPage::ShowInfoBar(muxc::InfoBarSeverity severity, hstring message)
{
    this->InfoBar().Severity(severity);
    this->InfoBar().Message(message);
    this->InfoBar().IsOpen(true);
}

bool winrt::CNS::implementation::MainPage::CheckComboBoxSelection()
{
    if ((this->ToFSelected==true)&&(this->DoASelected==true)&&(this->MoSSelected==true)&&(this->RoSSelected==true))
    {
        return true;
    }
    else
    {
        ShowInfoBar(muxc::InfoBarSeverity::Error, L"Fill all the information to continue!");
        return false;
    }
}

fire_and_forget winrt::CNS::implementation::MainPage::BrowseButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    auto lifetime = get_strong();
    FileOpenPicker openPicker;
    openPicker.ViewMode(PickerViewMode::Thumbnail);
    openPicker.SuggestedStartLocation(PickerLocationId::ComputerFolder);
    if (ButtonState==false)//decrypt
    {
        if (this->DoA==L"DES")
        {
            openPicker.FileTypeFilter().Append(L".des");
        }
        else
        {
            openPicker.FileTypeFilter().Append(L".aes");
        }
    }
    else
    {
        openPicker.FileTypeFilter().Append(L"*");
    }
    StorageFile file = co_await openPicker.PickSingleFileAsync();
    if (file != nullptr)
    {
        if (ButtonState == true)//encrypt
        {
            this->FileName = file.DisplayName();//file name
            this->FileType = file.FileType();//file type
            this->DisplayType = file.DisplayType();//display name
        }
        IBuffer buff = co_await FileIO::ReadBufferAsync(file);
        bufferText = CryptographicBuffer::EncodeToHexString(buff);
        this->ContentButton().Content(winrt::box_value(file.Name()));
        if (this->ContentButton().Visibility() != Visibility::Visible)
        {
            this->ContentButton().Visibility(Visibility::Visible);
        }
        if (this->CancelButton().Visibility() != Visibility::Visible)
        {
            this->CancelButton().Visibility(Visibility::Visible);
        }
        if (this->SaveButton().Visibility() != Visibility::Visible)
        {
            this->SaveButton().Visibility(Visibility::Visible);
        }
    }
    else
    {
        ShowInfoBar(muxc::InfoBarSeverity::Error, L"Open file error!");
    }
}


void winrt::CNS::implementation::MainPage::CancelButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    bufferText.empty();
    if (this->ContentButton().Visibility() == Visibility::Visible)
    {
        this->ContentButton().Visibility(Visibility::Collapsed);
    }
    if (this->CancelButton().Visibility() == Visibility::Visible)
    {
        this->CancelButton().Visibility(Visibility::Collapsed);
    }
    if (this->SaveButton().Visibility() == Visibility::Visible)
    {
        this->SaveButton().Visibility(Visibility::Collapsed);
    }
}


void winrt::CNS::implementation::MainPage::ActionButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    if (CheckComboBoxSelection())//all selected
    {
        hstring LText = L"";
        if (this->ToF==L"Text")//text
        {
            LText = this->LTextBox().Text();//read text
        }
        else//file
        {
            LText = bufferText;
        }
        if (LText != L"")
        {
            if (ButtonState == true)//encrypt
            {
                EncryptAsync(LText);
            }
            else//decrypt
            {
                DecryptAsync(LText);
                /*
                CypherKey = this->RKTextBox().Text();
                //decrypt key
                hstring PlainKey = RSAReceive.Decrypt(CypherKey);
                hstring TotalText = L"";
                //decrypt the message
                if (this->DoA == L"DES")//DES
                {
                    MyDES DES;
                    DES.Key(PlainKey);
                    DES.IV(this->IV);
                    TotalText = DES.DESCBC(CryptographicBuffer::DecodeFromHexString(LText), ButtonState);
                }
                else//AES
                {
                    MyAES AES;
                    AES.Key(PlainKey);
                    AES.IV(this->IV);
                    TotalText = AES.AESCBC(CryptographicBuffer::DecodeFromHexString(LText), ButtonState);
                }
                hstring SignedHashText = L"";
                hstring PlainText = L"";
                for (uint32_t i = 0; i < SignedHashTextSize; i++)
                {
                    SignedHashText = SignedHashText + TotalText[i];
                }
                for (uint32_t i = SignedHashTextSize; i < SignedHashTextSize + PlainTextSize; i++)
                {
                    PlainText = PlainText + TotalText[i];
                }
                hstring HashText = L"";
                //decrypt hash value and verify
                if (this->MoS == L"MD5")//MD5
                {
                    MyMD5 MD5;
                    HashText = CryptographicBuffer::EncodeToHexString(MD5.MD5(CryptographicBuffer::ConvertStringToBinary(PlainText, BinaryStringEncoding::Utf8)));
                }
                else
                {
                    MySHA256 SHA256;
                    HashText = CryptographicBuffer::EncodeToHexString(SHA256.SHA256(CryptographicBuffer::ConvertStringToBinary(PlainText, BinaryStringEncoding::Utf8)));
                }
                if (RSASend.Verify(SignedHashText, HashText))
                {
                    ShowInfoBar(muxc::InfoBarSeverity::Success, L"Message received correctly!");
                }
                else
                {
                    ShowInfoBar(muxc::InfoBarSeverity::Error, L"Message received with errors!");
                }
                if (this->ToF == L"Text")
                {
                    this->RTextBox().Text(PlainText);
                }
                else
                {
                    bufferText = PlainText;
                }*/
            }
        }
        else
        {
            if (this->ToF==L"Text")
            {
                ShowInfoBar(muxc::InfoBarSeverity::Error, L"Input some text to continue!");
            }
            else
            {
                ShowInfoBar(muxc::InfoBarSeverity::Error, L"Select a file to continue!");
            }
        }
    }
}

void winrt::CNS::implementation::MainPage::ToFBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->ToF = unbox_value<hstring>(e.AddedItems().GetAt(0));
    this->InfoBar().IsOpen(false);
    if (this->ToF==L"File")
    {
        this->BrowseButton().IsEnabled(true);
    }
    else
    {
        this->BrowseButton().IsEnabled(false);
    }
    this->ToFSelected = true;
}


void winrt::CNS::implementation::MainPage::DoABoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->DoA = unbox_value<hstring>(e.AddedItems().GetAt(0));
    this->InfoBar().IsOpen(false);
    this->DoASelected = true;
}


void winrt::CNS::implementation::MainPage::MoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->MoS = unbox_value<hstring>(e.AddedItems().GetAt(0));
    this->InfoBar().IsOpen(false);
    this->MoSSelected = true;
}


void winrt::CNS::implementation::MainPage::RoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->RoS = unbox_value<hstring>(e.AddedItems().GetAt(0));
    this->InfoBar().IsOpen(false);
    if (this->RoS==L"Manual")
    {
        this->SKeyBox().IsEnabled(true);
    }
    else
    {
        this->SKeyBox().IsEnabled(false);
    }
    this->RoSSelected = true;
}

void winrt::CNS::implementation::MainPage::GenerateRSAButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    InitRSAAsync();

}


fire_and_forget winrt::CNS::implementation::MainPage::SaveButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    auto lifetime = get_strong();
    FileSavePicker savePicker;
    savePicker.SuggestedStartLocation(PickerLocationId::ComputerFolder);
    if (ButtonState==true)//encrypt
    {
        savePicker.SuggestedFileName(this->FileName);
        if (this->DoA == L"DES")
        {
            auto DESExtensions{ winrt::single_threaded_vector<winrt::hstring>() };
            DESExtensions.Append(L".des");
            savePicker.FileTypeChoices().Insert(L"Cypher Text", DESExtensions);
        }
        else
        {
            auto AESExtensions{ winrt::single_threaded_vector<winrt::hstring>() };
            AESExtensions.Append(L".aes");
            savePicker.FileTypeChoices().Insert(L"Cypher Text", AESExtensions);
        }
    }
    else//decrypt
    {
        auto CommonExtensions{ winrt::single_threaded_vector<winrt::hstring>() };
        CommonExtensions.Append(this->FileType);
        savePicker.FileTypeChoices().Insert(this->DisplayType, CommonExtensions);
        savePicker.SuggestedFileName(this->FileName);
    }
    StorageFile file = co_await savePicker.PickSaveFileAsync();
    if (file != nullptr)
    {
        IBuffer buff = CryptographicBuffer::DecodeFromHexString(bufferText);
        co_await FileIO::WriteBufferAsync(file, buff);
        if (this->ContentButton().Visibility() == Visibility::Visible)
        {
            this->ContentButton().Visibility(Visibility::Collapsed);
        }
        if (this->CancelButton().Visibility() == Visibility::Visible)
        {
            this->CancelButton().Visibility(Visibility::Collapsed);
        }
        if (this->SaveButton().Visibility() == Visibility::Visible)
        {
            this->SaveButton().Visibility(Visibility::Collapsed);
        }
        ShowInfoBar(muxc::InfoBarSeverity::Success, L"Save file success!");
        bufferText.empty();
    }
    else
    {
        ShowInfoBar(muxc::InfoBarSeverity::Error, L"Save file error!");
    }
}

#include "pch.h"
#include "MyMD5.h"
#include "MySHA256.h"
#include "MyDES.h"
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
using namespace Windows::Globalization::NumberFormatting;

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


fire_and_forget winrt::CNS::implementation::MainPage::BrowseButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    auto lifetime = get_strong();
    FileOpenPicker openPicker;
    openPicker.ViewMode(PickerViewMode::Thumbnail);
    openPicker.SuggestedStartLocation(PickerLocationId::ComputerFolder);
    openPicker.FileTypeFilter().Append(L"*");
    StorageFile file = co_await openPicker.PickSingleFileAsync();
    if (file != nullptr)
    {
        //TODO: process file 
        if (this->ContentButton().Visibility() != Visibility::Visible)
        {
            this->ContentButton().Visibility(Visibility::Visible);
        }
        if (this->CancelButton().Visibility() != Visibility::Visible)
        {
            this->CancelButton().Visibility(Visibility::Visible);
        }
        //if (this->ActionButton().IsEnabled() == false)
        //{
        //    this->ActionButton().IsEnabled(true);
        //}
        this->ContentButton().Content(winrt::box_value(file.Name()));
    }
}


void winrt::CNS::implementation::MainPage::CancelButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    if (this->ContentButton().Visibility() == Visibility::Visible)
    {
        this->ContentButton().Visibility(Visibility::Collapsed);
    }
    if (this->CancelButton().Visibility() == Visibility::Visible)
    {
        this->CancelButton().Visibility(Visibility::Collapsed);
    }
    //if (this->ActionButton().IsEnabled() == true)
    //{
    //    this->ActionButton().IsEnabled(false);
    //}
}


void winrt::CNS::implementation::MainPage::ActionButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e)
{
    //this->RTextBox().Text(to_hstring(plaintext));
    if (this->ToF==L"Text")//Text Encrypt
    {
        LText = this->LTextBox().Text();
        if (LText == L"")//no text
        {
            this->InfoBar().Severity(muxc::InfoBarSeverity::Error);
            this->InfoBar().Message(hstring(L"Input Some Text!"));
            this->InfoBar().IsOpen(true);
        }
        else
        {
            if (ButtonState==true)//encrypt
            {
                IBuffer buffUtf8Msg = CryptographicBuffer::ConvertStringToBinary(LText, BinaryStringEncoding::Utf8);
                bool HashFinish = false;
                if (this->MoS == L"MD5")//MD5
                {
                    IBuffer MybuffHash = md5.MD5(buffUtf8Msg);
                    HashText = CryptographicBuffer::EncodeToHexString(MybuffHash);
                    HashFinish = true;
                }
                else if (this->MoS == L"SHA-256")//SHA 256
                {
                    IBuffer MybuffHash = sha256.SHA256(buffUtf8Msg);
                    HashText = CryptographicBuffer::EncodeToHexString(MybuffHash);
                    HashFinish = true;
                }
                else
                {
                    this->InfoBar().Severity(muxc::InfoBarSeverity::Error);
                    this->InfoBar().Message(hstring(L"Select Hash Method!"));
                    this->InfoBar().IsOpen(true);
                }
                if (HashFinish == true)//do symmetric encryption
                {
                    bool PasswordFinish = false;
                    uint32_t seed = 0;
                    if (this->RoS==L"Random")
                    {
                        des.GenerateSymmetricKey64();
                        PasswordFinish = true;
                    }
                    else if (this->RoS == L"Manual")
                    {
                        des.GenerateSymmetricKey64(SKeyBox().Password());
                        PasswordFinish = true;
                    }
                    else
                    {
                        this->InfoBar().Severity(muxc::InfoBarSeverity::Error);
                        this->InfoBar().Message(hstring(L"Select random password or manual password!"));
                        this->InfoBar().IsOpen(true);
                    }
                    if (PasswordFinish == true)
                    {
                        if (this->DoA==L"DES")
                        {
                            CypherText=des.DESCBC(buffUtf8Msg, ButtonState);
                        }
                        else if (this->DoA == L"AES-128")
                        {

                        }
                        else
                        {
                            this->InfoBar().Severity(muxc::InfoBarSeverity::Error);
                            this->InfoBar().Message(hstring(L"Select DES or AES-128!"));
                            this->InfoBar().IsOpen(true);
                        }
                    }
                }
                this->RTextBox().Text(HashInfo + HashText + CypherInfo + CypherText);
            }
            else//decrypt
            {
                IBuffer buffUtf8Msg = CryptographicBuffer::DecodeFromHexString(LText);
                hstring a = des.DESCBC(buffUtf8Msg, ButtonState);
                this->RTextBox().Text(a);
            }
        }
    }
    else if (this->ToF == L"File")//File Encrypt
    {

    }
    else
    {
        this->InfoBar().Severity(muxc::InfoBarSeverity::Error);
        this->InfoBar().Message(hstring(L"Select text encrypt or file encrypt!"));
        this->InfoBar().IsOpen(true);
    }
}





void winrt::CNS::implementation::MainPage::ToFBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->ToF = unbox_value<hstring>(e.AddedItems().GetAt(0));
    this->InfoBar().IsOpen(false);
}


void winrt::CNS::implementation::MainPage::DoABoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->DoA = unbox_value<hstring>(e.AddedItems().GetAt(0));
    this->InfoBar().IsOpen(false);
}


void winrt::CNS::implementation::MainPage::MoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->MoS = unbox_value<hstring>(e.AddedItems().GetAt(0));
    this->InfoBar().IsOpen(false);
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
}
﻿#include "pch.h"
#include "MainPage.h"
#include "MainPage.g.cpp"

using namespace std;
using namespace winrt;
using namespace Windows::UI::Xaml;
using namespace Windows::Foundation;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;

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
    if (ButtonState == TRUE)
    {
        ButtonState = FALSE;
        this->LTextBox().Header(winrt::box_value(L"Enter your ciphertext:"));
        this->LTextBox().PlaceholderText(L"Ciphertext");
        this->RTextBox().Header(winrt::box_value(L"Your plaintext:"));
        this->RTextBox().PlaceholderText(L"Plaintext");
        this->ActionButton().Content(winrt::box_value(L"Decrypt"));
    }
    else if (ButtonState == FALSE)
    {
        ButtonState = TRUE;
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
    string plaintext = to_string(this->LTextBox().Text());
    this->RTextBox().Text(to_hstring(plaintext));
    if (this->ToF==L"Text")//Text Encrypt
    {
        if (this->MoS==L"MD5")//MD5
        {

        }
        else if (this->MoS == L"SHA-256")//SHA 256
        {

        }
        else
        {
            throw hresult_not_implemented();
        }
    }
    else if (this->ToF == L"File")//File Encrypt
    {

    }
    else
    {
        throw hresult_not_implemented();
    }
}





void winrt::CNS::implementation::MainPage::ToFBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->ToF = unbox_value<hstring>(e.AddedItems().GetAt(0));
}


void winrt::CNS::implementation::MainPage::DoABoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->DoA = unbox_value<hstring>(e.AddedItems().GetAt(0));
}


void winrt::CNS::implementation::MainPage::MoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->MoS = unbox_value<hstring>(e.AddedItems().GetAt(0));
}


void winrt::CNS::implementation::MainPage::RoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e)
{
    this->RoS = unbox_value<hstring>(e.AddedItems().GetAt(0));
}

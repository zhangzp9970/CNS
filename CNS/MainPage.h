#pragma once
#include "pch.h"
#include "MyMD5.h"
#include "MySHA256.h"
#include "MyDES.h"
#include "MyAES.h"
#include "MyRSA.h"
#include "MainPage.g.h"

namespace muxc
{
    using namespace winrt::Microsoft::UI::Xaml::Controls;
};

namespace wuxc
{
    using namespace winrt::Windows::UI::Xaml::Controls;
};

namespace winrt::CNS::implementation
{
    struct MainPage : MainPageT<MainPage>
    {
        MainPage();

        int32_t MyProperty();
        void MyProperty(int32_t value);
        void ExchangeButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);

    private:
        bool ButtonState = true;//encrypt
        hstring ToF;
        bool ToFSelected = false;
        hstring DoA;
        bool DoASelected = false;
        hstring MoS;
        bool MoSSelected = false;
        hstring RoS;
        bool RoSSelected = false;
        uint32_t SignedHashTextSize = 0;
        uint32_t PlainTextSize = 0;
        hstring CypherText = L"";
        hstring CypherKey = L"";
        hstring IV = L"";
        hstring bufferText = L"";
        hstring FileType = L"";
        hstring DisplayType = L"";
        hstring FileName = L"";
        MyRSA RSASend;
        MyRSA RSAReceive;
        IAsyncAction InitRSAAsync();
        IAsyncAction EncryptAsync(hstring LText);
        IAsyncAction DecryptAsync(hstring LText);
        void ShowInfoBar(muxc::InfoBarSeverity severity, hstring message);
        bool CheckComboBoxSelection();
    public:
        fire_and_forget BrowseButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
        void CancelButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
        void ActionButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
        
        void ToFBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
        void DoABoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
        void MoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
        void RoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
        void GenerateRSAButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
        fire_and_forget SaveButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
    };
}

namespace winrt::CNS::factory_implementation
{
    struct MainPage : MainPageT<MainPage, implementation::MainPage>
    {
    };
}

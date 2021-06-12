#pragma once
#include "MyMD5.h"
#include "MySHA256.h"
#include "MyDES.h"
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
        hstring DoA;
        hstring MoS;
        hstring RoS;
        hstring LText = L"";
        hstring HashText = L"";
        hstring CypherText = L"";
        //hstring SymmetricKey = L"";
        hstring HashInfo = L"The hash value is: \n";
        hstring CypherInfo = L"\nThe encrypted text is: \n";
        MyMD5 md5;
        MySHA256 sha256;
        MyDES des;
    public:
        fire_and_forget BrowseButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
        void CancelButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
        void ActionButtonClick(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::RoutedEventArgs const& e);
        
        void ToFBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
        void DoABoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
        void MoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
        void RoSBoxSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Controls::SelectionChangedEventArgs const& e);
    };
}

namespace winrt::CNS::factory_implementation
{
    struct MainPage : MainPageT<MainPage, implementation::MainPage>
    {
    };
}

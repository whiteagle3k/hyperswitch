use std::net::IpAddr;

use common_utils::{errors::CustomResult, pii::Email};
use error_stack::ResultExt;
use masking::Secret;
use router_env::{env, logger, Env as RuntimeEnv};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use url::Url;

use crate::{
    connector::utils::{self, PaymentsAuthorizeRequestData},
    core::errors,
    services,
    types::{self, api, domain, storage::enums},
};

//TODO: Fill the struct with respective fields
pub struct MakecommerceRouterData<T> {
    pub amount: f64, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T>
    TryFrom<(
        &api::CurrencyUnit,
        enums::Currency,
        i64,
        T,
    )> for MakecommerceRouterData<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (currency_unit, currency, amount, item): (
            &api::CurrencyUnit,
            enums::Currency,
            i64,
            T,
        ),
    ) -> Result<Self, Self::Error> {
        let amount = utils::get_amount_as_f64(currency_unit, amount, currency)?;
        Ok(Self {
            amount,
            router_data: item,
        })
    }
}

// Auth Struct
pub struct MakecommerceAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) shop_id: Secret<String>,
}

impl TryFrom<&types::ConnectorAuthType> for MakecommerceAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &types::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            types::ConnectorAuthType::BodyKey {
                api_key,
                key1
            } => Ok(Self {
                api_key: api_key.to_owned(),
                shop_id: key1.to_owned()
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct IntegrationDetails {
    pub software: Option<String>,
    pub version: Option<String>,
    pub integration: Option<String>,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Default,
)]
pub enum TokenAgreement {
    #[serde(rename = "unscheduled")]
    #[default]
    Unscheduled,
    #[serde(rename = "recurring")]
    Recurring,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub amount: String,
    pub currency: String,
    pub reference: String,
    pub merchant_data: String,
    pub recurring_required: String,
    pub return_url: String,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct Customer {
    pub email: Option<Email>,
    pub ip: String,
    pub country: String,
    pub locale: String,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct AppInfo {
    pub module: String,
    pub module_version: String,
    pub platform: String,
    pub platform_version: String,
}

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize)]
pub struct MakecommercePaymentsRequest {
    pub transaction: Transaction,
    pub customer: Customer,
    pub app_info: AppInfo,
}

impl TryFrom<&MakecommerceRouterData<&types::PaymentsAuthorizeRouterData>> for MakecommercePaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &MakecommerceRouterData<&types::PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            domain::PaymentMethodData::CardRedirect(
                domain::CardRedirectData::CardRedirect {},
            ) => {
                logger::debug!("Received the router data {:?}", &item.router_data);

                let complete_auth_url = if env::which().to_string()
                    == RuntimeEnv::Development.to_string()
                {
                    // Use return url in dev env as "localhost" is not a valid cutomer_url
                    logger::debug!(
                        "====================> Development env detected. Complete the auth with: {:?} <====================",
                        &item.router_data.request.complete_authorize_url
                    );
                    item.router_data.return_url.clone()
                } else {
                    item.router_data.request.complete_authorize_url.clone()
                };

                // let merchant_id_string = item.router_data.merchant_id.clone().to_uppercase();
                // let timestamp_string = time.unix_timestamp().to_string().clone();
                // let len = timestamp_string.len();

                //let order_reference_string = format!("{}-{}", &merchant_id_string[..2], &timestamp_string[len-5..]);
                let transaction = Transaction {
                    amount: item.amount.to_string(),
                    currency: item.router_data.request.currency.to_owned().to_string(),
                    reference: item.router_data.connector_request_reference_id.to_owned(),
                    merchant_data: "".to_string(),
                    recurring_required: "false".to_string(),
                    return_url: complete_auth_url.ok_or(
                        errors::ConnectorError::InvalidConnectorConfig {
                            config: ("complete_authorize_url"),
                        },
                    )?,
                };

                let ip_addr: Option<IpAddr> = item.router_data.request.get_browser_info().map(|info| info.ip_address).unwrap_or(None);
                let ip_addr_string: String = ip_addr.map(|ip| ip.to_string()).unwrap_or("".to_string());

                let customer = Customer {
                    email: item.router_data.request.email.clone(),
                    ip: ip_addr_string,
                    country: "ee".to_string(),
                    locale: "en".to_string(),
                };
        
                let app_info = AppInfo {
                    module: "MakeCommerce Connector".to_string(),
                    module_version: "1.0.0".to_string(),
                    platform: "hyperswitch.io".to_string(),
                    platform_version: "1.151.1".to_string(),
                };

                Ok(Self {
                    transaction,
                    customer,
                    app_info,
                    ..MakecommercePaymentsRequest::default()
                })
            }
            _ => Err(
                errors::ConnectorError::NotImplemented("Payment methods".to_string()).into(),
            ),
        }
    }
}

fn get_country_code(
    address: Option<&api_models::payments::Address>,
) -> Option<common_enums::CountryAlpha2> {
    address
        .and_then(|billing| billing.address.as_ref().and_then(|address| address.country))
        .map(|country| match country {
            common_enums::CountryAlpha2::EE
            | common_enums::CountryAlpha2::LT
            | common_enums::CountryAlpha2::LV => country,
            _ => common_enums::CountryAlpha2::EE,
        })
}

// PaymentsResponse
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MakecommercePaymentStatus {
    #[default]
    Initial,
    WaitingForSca,
    WaitingFor3dsResponse,
    SentForProcessing,
    Abandoned,
    Failed,
    Settled,
    Authorised,
    Voided,
    Refunded,
    Chargebacked,
    CREATED,
}

impl From<MakecommercePaymentStatus> for enums::AttemptStatus {
    fn from(item: MakecommercePaymentStatus) -> Self {
        match item {
            MakecommercePaymentStatus::Initial => Self::AuthenticationPending,
            MakecommercePaymentStatus::Abandoned => Self::AuthorizationFailed,
            MakecommercePaymentStatus::Failed => Self::Failure,
            MakecommercePaymentStatus::Settled => Self::Charged,
            MakecommercePaymentStatus::CREATED => Self::Authorized,
            MakecommercePaymentStatus::WaitingForSca | MakecommercePaymentStatus::WaitingFor3dsResponse => {
                Self::Authorizing
            }
            MakecommercePaymentStatus::Authorised => Self::Authorized,
            MakecommercePaymentStatus::Voided => Self::Voided,
            _ => Self::Pending,
        }
    }
}


#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MakecommercePaymentsResponse {
    pub _links: Links,
    pub amount: f64,
    pub country: String,
    pub created_at: String,
    pub currency: String,
    pub id: String,
    pub status: MakecommercePaymentStatus,
    pub payment_methods: PaymentMethods,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Links {
    #[serde(rename = "Pay")]
    pay: Href,
    #[serde(rename = "self")]
    self_link: Href,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Href {
    href: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct PaymentMethods {
    cards: Vec<Card>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Card {
    url: String,
}

impl<F>
    TryFrom<
        types::ResponseRouterData<
            F,
            MakecommercePaymentsResponse,
            types::PaymentsAuthorizeData,
            types::PaymentsResponseData,
        >,
    > for types::RouterData<F, types::PaymentsAuthorizeData, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            MakecommercePaymentsResponse,
            types::PaymentsAuthorizeData,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        let redirect_url = Url::parse(item.response.payment_methods.cards[0].url.as_str())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        logger::debug!("Received the redirect url {:?}", &redirect_url);

        let redirection_data = get_redirect_url_form(redirect_url).ok();
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(
                    item.response.id,
                ),
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charge_id: None,
            }),
            ..item.data
        })
    }
}

fn get_redirect_url_form(
    redirect_url: Url,
) -> CustomResult<services::RedirectForm, errors::ConnectorError> {
    Ok(services::RedirectForm::from((
        redirect_url,
        services::Method::Get,
    )))
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MakecommercePaymentSyncRequest {
    pub payment_reference: String,
}

impl TryFrom<&types::PaymentsSyncRouterData> for MakecommercePaymentSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsSyncRouterData) -> Result<Self, Self::Error> {
        let payment_reference = item
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(Self {
            payment_reference,
        })
    }
}

impl TryFrom<&types::PaymentsCompleteAuthorizeRouterData> for MakecommercePaymentSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsCompleteAuthorizeRouterData) -> Result<Self, Self::Error> {
        let payment_reference = item
            .request
            .connector_transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(Self {
            payment_reference,
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MakecommercePaymentSyncResponse {
    pub payment_reference: String,
    pub payment_state: MakecommercePaymentStatus,
}

impl<F, T>
    TryFrom<
        types::ResponseRouterData<F, MakecommercePaymentSyncResponse, T, types::PaymentsResponseData>,
    > for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            MakecommercePaymentSyncResponse,
            T,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.payment_state),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(
                    item.response.payment_reference,
                ),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charge_id: None,
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Serialize)]
pub struct MakecommerceRefundRequest {
    pub amount: f64,
    pub payment_reference: String,
    pub nonce: String,
    pub timestamp: String,
}

impl<F> TryFrom<&MakecommerceRouterData<&types::RefundsRouterData<F>>> for MakecommerceRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &MakecommerceRouterData<&types::RefundsRouterData<F>>,
    ) -> Result<Self, Self::Error> {
        let auth_data = MakecommerceAuthType::try_from(&item.router_data.connector_auth_type)?;
        let time = OffsetDateTime::now_utc();

        Ok(Self {
            amount: item.amount.to_owned(),
            payment_reference: item.router_data.request.connector_transaction_id.to_owned(),
            nonce: time.unix_timestamp().to_string(),
            timestamp: time
                .format(&Iso8601::DEFAULT)
                .change_context(errors::ConnectorError::DateFormattingFailed)?,
        })
    }
}

impl From<MakecommercePaymentStatus> for enums::RefundStatus {
    fn from(item: MakecommercePaymentStatus) -> Self {
        match item {
            MakecommercePaymentStatus::Refunded => Self::Success,
            MakecommercePaymentStatus::Failed => Self::Failure,
            MakecommercePaymentStatus::SentForProcessing => Self::Pending,
            _ => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MakecommerceRefundResponse {
    pub initial_amount: f64,
    pub standing_amount: f64,
    pub transaction_time: String,
    pub payment_reference: String,
    pub payment_state: MakecommercePaymentStatus,
}

impl TryFrom<types::RefundsResponseRouterData<api::Execute, MakecommerceRefundResponse>>
    for types::RefundsRouterData<api::Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<api::Execute, MakecommerceRefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                connector_refund_id: item.response.payment_reference,
                refund_status: enums::RefundStatus::from(item.response.payment_state),
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MakecommerceRefundSyncRequest {
    pub payment_reference: String,
}

impl TryFrom<&types::RefundSyncRouterData> for MakecommerceRefundSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefundSyncRouterData) -> Result<Self, Self::Error> {
        let payment_reference = item.request.connector_transaction_id.to_owned();
        Ok(Self {
            payment_reference,
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MakecommerceRefundSyncResponse {
    pub payment_reference: String,
    pub payment_state: MakecommercePaymentStatus,
}
impl<T> TryFrom<types::RefundsResponseRouterData<T, MakecommerceRefundSyncResponse>>
    for types::RefundsRouterData<T>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<T, MakecommerceRefundSyncResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                // no refund id is generated, rather transaction id is used for referring to status in refund also
                connector_refund_id: item.response.payment_reference,
                refund_status: enums::RefundStatus::from(item.response.payment_state),
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct MakecommerceErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}
use common_utils::{errors::CustomResult, pii::Email};
use error_stack::ResultExt;
use masking::Secret;
use router_env::{env, logger, Env as RuntimeEnv};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use url::Url;

use crate::{
    connector::utils,
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
    pub(super) api_username: Secret<String>,
    pub(super) api_secret: Secret<String>,
    pub(super) account_name: Secret<String>,
    pub(super) base_url: Secret<String>,
}

impl TryFrom<&types::ConnectorAuthType> for MakecommerceAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &types::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            types::ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                api_username: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
                account_name: key1.to_owned(),
                base_url: key2.to_owned(),
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

#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Serialize)]
pub struct MakecommercePaymentsRequest {
    pub api_username: Secret<String>,
    pub account_name: Secret<String>,
    pub amount: f64,
    pub customer_url: String,
    pub token_agreement: TokenAgreement,
    pub mobile_payment: bool,
    pub order_reference: String,
    pub nonce: String,
    pub request_token: bool,
    pub token_consent_agreed: bool,
    pub timestamp: String,

    pub token_lifetime: Option<i32>,
    pub payment_description: Option<String>,

    pub email: Option<Email>,
    pub customer_ip: Option<String>,
    pub preferred_country: Option<common_enums::CountryAlpha2>,
    pub billing_city: Option<String>,
    pub billing_country: Option<String>,
    pub billing_line1: Option<String>,
    pub billing_line2: Option<String>,
    pub billing_line3: Option<String>,
    pub billing_postcode: Option<String>,
    pub billing_state: Option<String>,
    pub shipping_city: Option<String>,
    pub shipping_country: Option<String>,
    pub shipping_line1: Option<String>,
    pub shipping_line2: Option<String>,
    pub shipping_line3: Option<String>,
    pub shipping_code: Option<String>,
    pub shipping_state: Option<String>,
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
                let auth_data =
                    MakecommerceAuthType::try_from(&item.router_data.connector_auth_type)?;
                let time = OffsetDateTime::now_utc();

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

                Ok(Self {
                    api_username: auth_data.api_username,
                    account_name: auth_data.account_name,
                    amount: item.amount,
                    customer_url: complete_auth_url.ok_or(
                        errors::ConnectorError::InvalidConnectorConfig {
                            config: ("complete_authorize_url"),
                        },
                    )?,
                    token_agreement: TokenAgreement::Unscheduled,
                    mobile_payment: false,
                    order_reference: item.router_data.connector_request_reference_id.to_owned(), //order_reference_string,
                    nonce: time.unix_timestamp().to_string(),
                    request_token: true,
                    payment_description: item.router_data.description.clone(),
                    email: item.router_data.request.email.clone(),
                    customer_ip: None,
                    preferred_country: get_country_code(
                        item.router_data.address.get_payment_billing(),
                    ),
                    token_consent_agreed: true,
                    timestamp: time
                        .format(&Iso8601::DEFAULT)
                        .change_context(errors::ConnectorError::DateFormattingFailed)?,
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
}

impl From<MakecommercePaymentStatus> for enums::AttemptStatus {
    fn from(item: MakecommercePaymentStatus) -> Self {
        match item {
            MakecommercePaymentStatus::Initial => Self::AuthenticationPending,
            MakecommercePaymentStatus::Abandoned => Self::AuthorizationFailed,
            MakecommercePaymentStatus::Failed => Self::Failure,
            MakecommercePaymentStatus::Settled => Self::Charged,
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
    pub payment_reference: String,
    pub payment_link: String,
    pub payment_state: MakecommercePaymentStatus,
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
        let redirect_url = Url::parse(item.response.payment_link.as_str())
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        logger::debug!("Received the redirect url {:?}", &redirect_url);

        let redirection_data = get_redirect_url_form(redirect_url).ok();
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.payment_state),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(
                    item.response.payment_reference,
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
    pub api_username: Secret<String>,
    pub detailed: bool,
    pub base_url: Secret<String>,
}

impl TryFrom<&types::PaymentsSyncRouterData> for MakecommercePaymentSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsSyncRouterData) -> Result<Self, Self::Error> {
        let auth_data = MakecommerceAuthType::try_from(&item.connector_auth_type)?;
        let payment_reference = item
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(Self {
            payment_reference,
            api_username: auth_data.api_username,
            detailed: true,
            base_url: auth_data.base_url,
        })
    }
}

impl TryFrom<&types::PaymentsCompleteAuthorizeRouterData> for MakecommercePaymentSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsCompleteAuthorizeRouterData) -> Result<Self, Self::Error> {
        let auth_data = MakecommerceAuthType::try_from(&item.connector_auth_type)?;
        let payment_reference = item
            .request
            .connector_transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
        Ok(Self {
            payment_reference,
            base_url: auth_data.base_url,
            api_username: auth_data.api_username,
            detailed: true,
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
    pub api_username: Secret<String>,
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
            api_username: auth_data.api_username,
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
    pub api_username: Secret<String>,
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
    pub api_username: Secret<String>,
    pub detailed: bool,
    pub base_url: Secret<String>,
}

impl TryFrom<&types::RefundSyncRouterData> for MakecommerceRefundSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefundSyncRouterData) -> Result<Self, Self::Error> {
        let auth_data = MakecommerceAuthType::try_from(&item.connector_auth_type)?;
        let payment_reference = item.request.connector_transaction_id.to_owned();
        Ok(Self {
            payment_reference,
            api_username: auth_data.api_username,
            detailed: true,
            base_url: auth_data.base_url,
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
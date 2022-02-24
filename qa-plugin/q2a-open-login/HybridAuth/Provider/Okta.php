<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2017 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\InvalidAccessTokenException;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\Data;
use Hybridauth\User;

/**
 * Github OAuth2 provider adapter.
 * https://coupang.oktapreview.com/.well-known/openid-configuration
 */
class Okta extends OAuth2
{


    /**
     * {@inheritdoc}
     */
    protected $apiBaseUrl = 'https://coupang.oktapreview.com/oauth2/default/v1/';

    /**
     * {@inheritdoc}
     */
    protected $authorizeUrl = 'https://coupang.oktapreview.com/oauth2/v1/authorize';

    /**
     * {@inheritdoc}
     */
    protected $accessTokenUrl = 'https://coupang.oktapreview.com/oauth2/v1/token';

    /**
     * {@inheritdoc}
     */
    protected $apiDocumentation = 'https://developer.github.com/v3/oauth/';

    /**
     * {@inheritdoc}
     */
    protected function initialize()
    {
        parent::initialize();


        $this->AuthorizeUrlParameters['scope'] = 'openid';
        $this->AuthorizeUrlParameters['redirect_uri'] = 'http://ip-10-213-104-139.ap-northeast-2.compute.internal/?hauth.done=Okta';
        $this->tokenExchangeParameters['redirect_uri'] = 'http://ip-10-213-104-139.ap-northeast-2.compute.internal/?hauth.done=Okta';
        $this->tokenRefreshParameters += [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];
    }


    /**
     * {@inheritdoc}
     */
    public function getUserProfile()
    {
        $response = $this->apiRequest('userinfo');

        $data = new Data\Collection($response);

        qa_debug($data);

        if (! $data->exists('email')) {
            throw new UnexpectedApiResponseException('Provider API returned an unexpected response.');
        }

        $userProfile = new User\Profile();

        $userProfile->identifier  = $data->get('sub');
        $userProfile->displayName = $data->get('preferred_username');
        $userProfile->email       = $data->get('email');
        $userProfile->language = $data->get('locale');


//        if (empty($userProfile->email) && strpos($this->scope, 'user:email') !== false) {
//            try {
//                $userProfile = $this->requestUserEmail($userProfile);
//            }
//                // user email is not mandatory so keep it quite
//            catch (\Exception $e) {
//            }
//        }

        return $userProfile;
    }

    /**
     * Request connected user email
     *
     * https://developer.github.com/v3/users/emails/
     */
    protected function requestUserEmail(User\Profile $userProfile)
    {
        $response = $this->apiRequest('user/emails');

        foreach ($response as $idx => $item) {
            if (! empty($item->primary) && $item->primary == 1) {
                $userProfile->email = $item->email;

                if (! empty($item->verified) && $item->verified == 1) {
                    $userProfile->emailVerified = $userProfile->email;
                }

                break;
            }
        }

        return $userProfile;
    }
}

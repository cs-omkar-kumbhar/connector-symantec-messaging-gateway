import requests
from bs4 import BeautifulSoup
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('symantec-messaging-gateway')
SENDER_GRP = 'reputation/sender-group/'
VIEW_SENDER_GRP = SENDER_GRP + 'viewSenderGroup.do'


class SMG:

    def __init__(self, config):
        self._session = requests.Session()
        self.verify_ssl = config.get("verify_ssl", False)
        base_url = config.get('base_url').strip('/') + '/brightmail/'
        if not base_url.startswith('https://'):
            base_url = 'https://' + base_url
        self.base_url = base_url


    def _make_request(self, endpoint, method='get', params=None):
        try:
            url = self.base_url + endpoint
            logger.info('Executing url {}'.format(url))
            call_method = getattr(self._session, method)
            response = call_method(url, params=params, verify=self.verify_ssl)
            if response.ok:
                logger.info('successfully get response for url {}'.format(url))
                return response
            elif response.status_code == 401:
                raise ConnectorError('Invalid endpoint or credentials')
            elif response.status_code == 403:
                raise ConnectorError('Unauthorized')
            elif response.status_code == 404:
                raise ConnectorError('URL not found')
            else:
                logger.error(response.content)
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))
        raise ConnectorError(response.content)

    def _login(self, config):
        try:
            resp = self._make_request('viewLogin.do', method='get')
            soup_obj = BeautifulSoup(resp.text, 'html.parser')
            lastlogin_tag = soup_obj.find('input', {'name': 'lastlogin'})
            if not lastlogin_tag:
                logger.error('Login failed, not able to find last login time in viewLogin response')
                raise ConnectorError('Login failed, not able to find last login time')
            lastlogin = lastlogin_tag['value']
            params = {'lastlogin': lastlogin,
                      'username': config['user_name'],
                      'password': config['password']}
            resp = self._make_request('/login.do', params=params)
            soup_obj = BeautifulSoup(resp.text, 'html.parser')
            token_tag = soup_obj.find('input', {'name': 'symantec.brightmail.key.TOKEN'})
            if not token_tag:
                logger.error('Login failed, Could not find token in login response')
                raise ConnectorError('Login failed, invalid input credentials')
            token = token_tag['value']
            logger.info('login successfully')
            return token
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def _is_exists(self, input, resp):
        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
            member_table = soup.find('table', {'id': 'membersList'})
            if not member_table:
                logger.error('Not able to find member list table')
                raise ConnectorError('Not able to find member list table')
            item_id = None
            member_tags = soup.findAll('tr')
            if not member_tags:
                logger.error('No items found in bad senders list')
                raise ConnectorError('No items found in bad senders list')
            for tag in member_tags:
                if input in tag.text:
                    checkbox = tag.find('input', {'name': 'selectedGroupMembers'})
                    if not checkbox:
                        logger.error('Item ID not for input {}'.format(input))
                        raise ConnectorError('Item ID not for input {}'.format(input))
                    item_id = checkbox['value']
                    break
            return item_id
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def _blacklist_item(self, config, input, sender_group):
        try:
            token = self._login(config)
            resp = self._make_request(VIEW_SENDER_GRP + '?view=badSenders')
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders',
                'selectedSenderGroups': sender_group
            }
            resp = self._make_request(VIEW_SENDER_GRP, params=params)
            resp = self._make_request(SENDER_GRP + 'addSender.do', params=params)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'addEditSenders': input,
                'view': 'badSenders'
            }
            resp = self._make_request(SENDER_GRP + 'saveSender.do', params=params)
            # Look for the error message
            soup = BeautifulSoup(resp.content, 'html.parser')
            error = soup.find('div', 'errorMessageText')
            if error:
                error_message = ' '.join(error.text.split())  # Removes whitespaces from string
                logger.error(error_message)
                raise ConnectorError(error_message)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders'
            }
            resp = self._make_request(SENDER_GRP + 'saveGroup.do', params=params)
            if resp.ok:
                return 'Successfully blacklisted {}'.format(input)
            logger.error(resp.content)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
        raise ConnectorError(resp.content)

    def _unblacklist_item(self, config, input, sender_group):
        try:
            token = self._login(config)
            resp = self._make_request(VIEW_SENDER_GRP + '?view=badSenders')
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders',
                'selectedSenderGroups': sender_group
            }
            resp = self._make_request(VIEW_SENDER_GRP, params=params)
            item_id = self._is_exists(input, resp)
            if not item_id:
                logger.error('Input not found in blacklist')
                raise ConnectorError('Input not found in blacklist')
            resp = self._make_request(SENDER_GRP + 'addSender.do', params=params)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'selectedGroupMembers': item_id,
                'view': 'badSenders',
                'selectedSenderGroups': sender_group
            }
            resp = self._make_request(SENDER_GRP + 'deleteSender.do', params=params)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders'
            }
            resp = self._make_request(SENDER_GRP + 'saveGroup.do', params=params)
            if resp.ok:
                return 'Successfully remove {} from blacklist'.format(input)
            logger.error(resp.content)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
        raise ConnectorError(resp.content)

    def blacklist_email(self, config, params):
        return self._blacklist_item(config, params.get('email_id', None), '1|3')

    def unblacklist_email(self, config, params):
        return self._unblacklist_item(config, params.get('email_id', None), '1|3')

    def blacklist_domain(self, config, params):
        return self._blacklist_item(config, params.get('domain', None), '1|3')

    def unblacklist_domain(self, config, params):
        return self._unblacklist_item(config, params.get('domain', None), '1|3')

    def blacklist_ip(self, config, params):
        return self._blacklist_item(config, params.get('ip', None), '1|1')

    def unblacklist_ip(self, config, params):
        return self._unblacklist_item(config, params.get('ip', None), '1|1')

    def test_connection(self, config):
        return self._login(config)




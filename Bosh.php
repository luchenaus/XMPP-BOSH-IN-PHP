<?php
class Bosh 
{
	protected $sid = ''; 
	protected $challenge = array(); 
	protected $domain = ''; 
	protected $bosh_url = ''; 
	protected $xmpp_share_key = ''; 
	protected $userId = 0; 
	protected $response = '';
	protected $passwd = '';
	protected $rid = 0; 

	public function __construct($bosh_url, $xmpp_share_key, $domain, $userId, $passwd)
	{
		$this->bosh_url = $bosh_url; 
		$this->xmpp_share_key = $xmpp_share_key; 		
		$this->domain = $domain; 
		$this->userId = $userId; 
		$this->passwd = $passwd; 
	}

	/**
	*@todo generate the xml for session request 
	*/
	public function generateSessionXml()
	{
		$xml = "<body content='text/xml; charset=utf-8' from='".$this->userId."@".$this->domain."'";
        $xml .= " hold='1' rid='".$this->userId."' to='".$this->domain."' route='".$this->bosh_url."' ver='1.6' wait='60' xml:lang='en' xmpp:version='1.0' xmlns='http://jabber.org/protocol/httpbind' xmlns:xmpp='urn:xmpp:xbosh'/>";
		return $xml; 
	}

	/**
	*@todo generate the xml request for sasl challenge
	*/
	public function generateSASLChallengeRequest()
	{
		$userId = $this->userId + 1; 
		$xml = "<body rid='".$userId."' sid='".$this->sid."' xmlns='http://jabber.org/protocol/httpbind' xmlns:xmpp='urn:xmpp:xbosh'>";
        $xml .= "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>".base64_encode("\x00" . $this->userId . "\x00" . $this->passwd)."</auth></body>";
		return $xml; 
	}	

	/**
	*@todo generate the xml request for sasl response (sasl step 2)
	*/
	public function generateSASLResponseRequest()
	{
		$userId = $this->userId + 2; 
		$xml = "<body rid='".$userId."' xmlns='http://jabber.org/protocol/httpbind' sid='".$this->sid."'><response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>".$this->response."</response></body>";
		return $xml; 
	}
	
	/**
	*@todo generate the xml of restart request 	
	*/
	public function generateRestartRequestXml()
	{
		$userId = $this->userId + 3;
		$this->rid = $userId; 
		$xml = "<body rid='".$userId."' sid='".$this->sid."' to='".$this->domain."' xml:lang='en' xmpp:restart='true' xmlns='http://jabber.org/protocol/httpbind' xmlns:xmpp='urn:xmpp:xbosh'/>";
		return $xml; 	
	}

	/**
 	*@todo generate resource binding request xml 
	 */
	public function generateBindingXml()
	{
		$userId = $this->userId + 3;
		$xml = "<body rid='".$userId."' sid='".$this->sid."' xmlns='http://jabber.org/protocol/httpbind'><iq id='bind_".$userId."' type='set' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq></body>";
		//$xml = "<body rid='".$userId."' route='".$this->bosh_url."' xmlns='http://jabber.org/protocol/httpbind' sid='".$this->sid."'><iq type='set' id='bind_1' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><resource>httpclient</resource></iq></body>";
		return $xml; 		
	}

	/**
	*@todo send bosh request to your openfire http bind url 
	*/
	public function boshCurl($xml)
    {
        try {
			$curl =  curl_init();
			curl_setopt($curl, CURLOPT_URL, $this->bosh_url);
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($curl, CURLOPT_HEADER, 1);
			curl_setopt($curl, CURLOPT_HTTPHEADER, array("Authorization: ".$this->xmpp_share_key, 'Accept-Encoding: gzip, deflate', "Content-Type: application/xml; charset=utf-8"));
			curl_setopt($curl, CURLOPT_POST, 1);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $xml);
			$return = curl_exec($curl);
			curl_close($curl);
			return $return;
        }catch(Exception $e) {
            return '';
        }
    }	
	
	/**
	*@todo get the session id 
	*/
	public function generateSid()
	{
		$xml = $this->generateSessionXml($this->userId);
		$return = $this->boshCurl($xml); 
		$position = strpos($return, "<body");
		if($position !== false) {
            $result = simplexml_load_string(substr($return, strpos($return, "<body")));
            foreach($result->attributes() as $k=>$v) {
                $k == 'sid' && $this->sid = (string)$v;
            }
		}
	}		
	
	/**
	*@todo get sasl challenge 
	*/
	public function generateChallenge()
	{
		if(!empty($this->sid)){
			$xml = $this->generateSASLChallengeRequest();
			$return = $this->boshCurl($xml);	
			$position = strpos($return, "<challenge");
            if($position !== false) {
            	$result = simplexml_load_string(substr($return, strpos($return, "<body")));
            	foreach($result->children() as $k=>$v) {
            		$k == 'challenge' && $this->challenge = base64_decode($v);
                }
				$challengeArray = array(); 
				if(!empty($this->challenge)){
					$challenge = $this->challenge; 
					while(preg_match('/([a-z]+)=("[^"]+"|[^,"]+)(?:,|$)/', $challenge, $matches)){
						$challenge = str_replace($matches[0], "", $challenge);
						$challengeArray[$matches[1]] = str_replace('"', '', $matches[2]);
					}
				}
				if(!empty($challengeArray)) {
					$this->challenge = $challengeArray; 
					unset($challengeArray);
				}
			}
		}
	}
	
	/**
	*@todo generate sasl response 
	*/
	public function generateSASLResponse()
	{
		$this->generateSid();
		$this->generateChallenge();
		if(!empty($this->challenge)) {
			$digest_uri = 'xmpp/'.$this->domain; 
			$cnounce = $this->generateClientNonce();
			$y = md5($this->userId . ':' . $this->challenge['realm'] . ':' . $this->passwd);
			$a1 = sprintf('%s:%s:%s:%s', $y, $this->challenge['nonce'], $cnounce, $this->userId . '@' . $this->domain);
			$a2 = 'AUTHENTICATE:' . $digest_uri;
			$ha1 = md5($a1);
			$ha2 = md5($a2);
			$this->response = base64_encode(md5(sprintf('%s:%s:00000001:%s:auth:%s', $ha1, $this->challenge['nonce'], $cnounce, $ha2)));
		}
	}
	
	/**
	*@todo send sasl response request 
	*/
	public function sendResponse()
	{
		$this->generateSASLResponse();
		if(!empty($this->response)) {
			$xml = $this->generateSASLResponseRequest();
			$return = $this->boshCurl($xml);
		}
	}
	
	/**
	*@todo send restart request to bosh 
	*/
	public function sendRestartRequest()
	{
		$this->sendResponse(); 
		$xml = $this->generateRestartRequestXml();
		$return = $this->boshCurl($xml);
	}

	/**
	*@todo send binding request to bosh 	
	*/
	public function sendBindingRequest() 
	{
		$this->sendRestartRequest(); 
		$xml = $this->generateBindingXml();
		$return = $this->boshCurl($xml); 
		//print_r($return);
	}

	/**
	*@todo test sending msg
	*/
	public function sendingTestMsg()
	{
		$userId = $this->userId + 3; 
		$xml = "<body rid='".$userId."' sid='".$this->sid."' xmlns='http://jabber.org/protocol/httpbind'>
  <message to='testuser@yourdomain' xmlns='jabber:client'>
    <body>Good morning!</body>
  </message>
</body>";
		$return = $this->boshCurl($xml);
		//print_r($return);
	}

	/**
	*@todo generate sasl client nonce 
	*/
	public function generateClientNonce()
	{
		$str = '';
		for ($i=0; $i<32; $i++) {
        	$str .= chr(mt_rand(0, 25535532));
    	}

        return base64_encode($str);
    }			
	
	/**
	*@todo get attach infor into session 
	*/
	public function getBoshAttachInfo()
	{
		$info['rid'] = $this->rid; 
		$info['sid'] = $this->sid; 
		return $info; 
	}
	
}

//$bosh = new Bosh('https://yourdomain:yourport/http-bind/', 'yourserverkey', 'yourdomain', username, passwd);
//$bosh->sendBindingRequest();
//$bosh->sendingTestMsg(); 
//print_r($bosh->getBoshAttachInfo());
//print_r($bosh);
?>

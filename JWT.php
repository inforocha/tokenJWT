<?php
/**
* O JWT eh um padrao aberto, documentado pelo RFC 7519. Com ele conseguimos transmitir informacoes, 
* garantindo a sua autenticidade, podendo ser usado na autenticacao de APIs, sistemas ou em acoes
* mais especificas, como recuperar a senha de um usuario, por exemplo.
* Um JWT é divido em tres partes separadas por ponto ”.”: um header, um payload e uma signature.
* 
* O header basicamente consiste em dois valores: um é o tipo do token, que nesse caso é JWT, 
* e o segundo valor é o algoritmo utilizado de hashing, como o HMAC SHA-256 ou RSA. No nosso caso, usaremos o HS256.
* 
* O JWT tem palavras reservadas e recomendadas para serem colocadas dentro do payload. São elas:
* “iss” O domínio da aplicação geradora do token
* “sub” É o assunto do token, mas é muito utilizado para guarda o ID do usuário
* “aud” Define quem pode usar o token
* “exp” Data para expiração do token
* “nbf” Define uma data para qual o token não pode ser aceito antes dela
* “iat” Data de criação do token
* “jti” O id do token
* 
* O signature é a nossa assinatura. 
* 
* RFC 7519: https://tools.ietf.org/html/rfc7519
* O site do JWT.io: https://jwt.io/
* 
* @version 1.0.1
*
* @example
* // criando novo token
* $jwt = new jwt();
* $token = $jwt->createJWT(
*	array(
*		'iss' => 'http://api.io',
*		'usuario_id' => 123456,
*		'codigo_empresa' => halbsvv09awe0w3rue,
*	)
* );
*
* @example
* // validando um token existente
* $jwt = new jwt();
* $token = $_GET['token']; // token enviado para a api
*
* if($jwt->verifyJWT($token)) {
*	echo 'TOKEN VALIDO';
* } else {
*	echo 'TOKEN INVALIDO';
* }
*/

class JWT {
	private $header = '';
	private $payload = '';
	private $signature = '';
	private $secret_key = 'SUA_CHAVE_SECRETA_AQUI';
	private $offset = 2; // em horas - validade do token
	private $errors = array(
		'URL_OBRIGATORIA' => 'Obrigatorio informar uma URL para o payload do token',
		'URL_NAO_VAZIA' => 'URL para o payload do token não pode ser vazia',
		'USUARIO_OBRIGATORIO' => 'Obrigatorio informar um usuario para o payload do token',
		'USUARIO_NAO_VAZIO' => 'Usuario para o payload do token não pode ser vazio',
		'TOKEN_REQUEST_INSISTENTE' => 'Obrigatorio informar o token do request',
		'TOKEN_ALTERADO' => 'Assinatura do token nao e identico ao original',
		'TOKEN_EXPIRADO' => 'Token expirado',
	);

	/***********************************************************************************************/
	/* METODOS DE GERACAO DO JWT                                                                   */
	/***********************************************************************************************/

	/**
	 * Encode data to Base64URL
	 * @param string $data
	 * @return boolean|string
	 */
	private function base64url_encode($data) {
		// First of all you should encode $data to Base64 string
		$b64 = base64_encode($data);

		// Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
		if ($b64 === false) {
			return false;
		}

		// Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
		$url = strtr($b64, '+/', '-_');

		// Remove padding character from the end of line and return the Base64URL result
		return rtrim($url, '=');
	}

	/**
	 * Decode data from Base64URL
	 * @param string $data
	 * @param boolean $strict
	 * @return boolean|string
	 */
	private function base64url_decode($data, $strict = false) {
		// Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
		$b64 = strtr($data, '-_', '+/');

		// Decode Base64 string and return the original data
		return base64_decode($b64, $strict);
	}

	/**
	* A classe ja possui um valor default. Esse metodo eh para casos em que queira altera-lo, por exemplo quando for gerar um token externo.
	* @param string - a nova chave
	* @return void
	*/
	public function setSecretKey($key) {
		$this->secret_key = $key;
	}

  /**
	* Cria um jason web token
	* @return string - token
	*/
	public function createJWT($base) {
		$this->setBasePayload($base);
		$this->setHeader();
		$this->setSignature();

		return "{$this->header}.{$this->payload}.{$this->signature}";
	}

	/**
	* Retorna o token atual atualizando sua data de criacao e de expiracao.
	* @return string
	*/
	public function refreshJWT() {
		$this->verifyJWT();

		// utilizar o mesmo payload alterando somente a data de expiracao e a data atual
		return $this->createJWT($this->token_response['payload']);
	}

	/***********************************************************************************************/
	/* METODOS QUE GUARDAM INFORMACAO DO JWT                                                                 */
	/***********************************************************************************************/
	private function setHeader() {
		// $header = array(
		// 	"alg" => "HS256",
		// 	"typ" => "JWT"
		// );

		// $header = json_encode($header);
		$header = '{"alg": "HS256","typ": "JWT"}';
		$this->header = $this->base64url_encode($header);
	}

	/**
	* Passando os dados para payload do token
	* @param object $base
	* @return void
	*/
	private function setBasePayload($base) {
		// if(!isset($base->iss)) throw new InvalidParam($this->errors['URL_OBRIGATORIA'], 1);
		// if(empty($base->iss)) throw new InvalidParam($this->errors['URL_NAO_VAZIA'], 1);
		
		// $now = date('Y-m-d H:i:s');

		// $base->iat = $now;
		// $base->exp = date('Y-m-d H:i:s', strtotime("{$now} +{$this->offset} hour"));

		$payload = json_encode($base);
		$this->payload = $this->base64url_encode($payload);
	}

	private function setSignature() {
		$this->signature = $this->createSignature($this->header, $this->payload);
	}

	/**
	* Seta o token na classe.
	* @return this
	*/
	public function setToken($token) {
		if(empty($token)) throw new InvalidToken($this->errors['TOKEN_REQUEST_INSISTENTE'], 1);

		list($header_base64, $payload_base64, $signature) = explode(".", $token);

		$this->token_response['header_base64'] = $header_base64; 
		$this->token_response['payload_base64'] = $payload_base64;
		$payload_decode = $this->base64url_decode($payload_base64); 
		$this->token_response['payload'] = json_decode($payload_decode);
		$this->token_response['signature'] = $signature;

		return $this;
	}

	/***********************************************************************************************/
	/* METODOS DE VALIDACAO DO JWT                                                                 */
	/***********************************************************************************************/

	/**
	* Criando assinatura, ou seja, um hash com os dados do header, payload e nossa chave secreta.
	* @param string $header
	* @param string $payload
	* @return string - signature
	*/
	private function createSignature($header, $payload) {
		$signature = hash_hmac('sha256', $header.'.'.$payload, $this->secret_key, true);
		return $this->base64url_encode($signature);		
	}

	/**
	* Verifica se o token eh valido. Caso nao seja dispara exception
	* OBSERVACAO: o token deve ter sido assinado por esta classe.
	* @return void
	*/
	public function verifyJWT() {
		if(!count($this->token_response)) throw new InvalidToken($this->errors['TOKEN_REQUEST_INSISTENTE'], 1);

		$this->tokenWasNotChanged();
		$this->refreshTokenBeforeExpiration();
	}

	/**
	* Verifica se o token nao foi alterado.
	* OBSERVACAO: o token deve ter sido assinado por esta classe.
	* @return void
	*/
	private function tokenWasNotChanged() {
		if(!count($this->token_response)) throw new InvalidToken($this->errors['TOKEN_REQUEST_INSISTENTE'], 1);
		// comparando assinatura do token com a assinatura gerada pela classe para saber se o token nao foi adulterado
		if ($this->token_response['signature'] != $this->createSignature($this->token_response['header_base64'], $this->token_response['payload_base64'])) {
			throw new InvalidToken($this->errors['TOKEN_ALTERADO'], 1);
		}
	}

	/**
	* Verifica se o token pode ser atualizado.
	* OBSERVACAO: o token deve ter sido assinado por esta classe.
	* @return void
	*/
	public function refreshTokenBeforeExpiration() {
		if(!count($this->token_response)) throw new InvalidToken($this->errors['TOKEN_REQUEST_INSISTENTE'], 1);
		$now = date('Y-m-d H:i:s');

		if (strtotime($now) > strtotime($this->token_response['payload']->exp)) {
			throw new InvalidToken($this->errors['TOKEN_EXPIRADO'], 1);
		}
	}
}

class InvalidToken extends Exception { }
class InvalidParam extends Exception { }

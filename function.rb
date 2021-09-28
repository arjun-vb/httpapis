# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  if event['httpMethod'] == 'POST' and event['path'] == '/token'
    if event['headers']['Content-Type'] != 'application/json'
      response(body: nil, status: 415)
    elsif isJson(event['body'])
      payload = {
        data: event['body'],
        exp: Time.now.to_i + 5,
        nbf: Time.now.to_i + 2
      }
      token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
      response(body: {"token": token}, status: 201)
    else
      response(body: nil, status: 422)
    end
  elsif event['httpMethod'] == 'GET' and event['path'] == '/'
    auth = event['headers']['Authorization']
    autharray = auth.split()
    if autharray[0] == 'Bearer' and autharray[1].length > 0
      begin
        decodeToken = JWT.decode autharray[1], ENV['JWT_SECRET'], 'HS256'
        response(body: decodeToken[0]['data'], status: 200)
      rescue JWT::ExpiredSignature, JWT::ImmatureSignature
        response(body: nil, status: 401)
      end
    else
      response(body: nil, status: 403)
    end
  elsif event['path'] == '/' or event['path'] == '/token'
    response(body: nil, status: 405)
  else
    response(body: nil, status: 404)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const querystring = require('querystring');
const cors = require('cors');

const app = express();
const port = 8080;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());

// Use the demo or live URL based on your environment
const convergeAPIUrl = 'https://api.convergepay.com/hosted-payments/transaction_token';

const merchantID = '2446101';
const merchantUserID = '8042061146web';
const merchantPIN = 'MHL8T6CBZ1XXZ9SFGLZJ83WUQX6FJZVSFR3AB6FXXN70WE1G985PIZZDEROC683F';

app.post('/get-session-token', async (req, res) => {
  const { ssl_first_name, ssl_last_name, ssl_amount } = req.body;

  const postData = querystring.stringify({
    ssl_merchant_id: merchantID,
    ssl_user_id: merchantUserID,
    ssl_pin: merchantPIN,
    ssl_transaction_type: 'ccsale',
    ssl_first_name,
    ssl_last_name,
    ssl_get_token: 'Y',
    ssl_add_token: 'Y',
    ssl_amount,
  });

  try {
    const response = await axios.post(convergeAPIUrl, postData, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      }
    });

    // The response will be the session token; send it back to the client
    console.log('Session token obtained successfully:', response.data);
    res.json({ sessionToken: response.data });
  } catch (error) {
    console.error('Error getting session token:', error.message);
    res.status(500).json({ error: 'Error getting session token.' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

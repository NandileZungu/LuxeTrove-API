// paypal.js
const paypal = require('paypal-rest-sdk');

paypal.configure({
    'mode': 'sandbox', //sandbox or live
    'client_id': 'AZZCWOjzXpKhgbXWJBYznw65EaqmUh0Rf5LojIDe5wF0ckx_GHRFrm5_H7FHEaTEQ15LrGG8TyACkEgy',
    'client_secret': 'ELXGpKVoTTVA58ftV_Y1FRnhv_yWv1EWMYXjN_DuiD5Wa0XaVjqmaWVpJznAv8NtgMJr15mSQUYnF-u_'
});

const createPayment = (req, res) => {
    const create_payment_json = {
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": "http://localhost:8080/success",
            "cancel_url": "http://localhost:8080/cancel"
        },
        "transactions": [{
            "item_list": {
                "items": req.body.items
            },
            "amount": {
                "currency": "USD",
                "total": req.body.total
            },
            "description": "This is the payment description."
        }]
    };

    paypal.payment.create(create_payment_json, (error, payment) => {
        if (error) {
            console.log(error);
            res.status(500).send(error);
        } else {
            for (let i = 0; i < payment.links.length; i++) {
                if (payment.links[i].rel === 'approval_url') {
                    res.json({ forwardLink: payment.links[i].href });
                }
            }
        }
    });
};

module.exports = { createPayment };
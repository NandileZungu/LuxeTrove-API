// stripe.js
const stripe = require('stripe')('sk_test_51PYQYLBoBI2Kef4Lz7UF51nq6N4mATzGPCdWmC5OVhGBezUkRvL2nBUMcNThe6Hb9DjvRnJkLVbdvTEBrXoirpDS00wENzZYX1');

const createCheckoutSession = async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: 'T-shirt',
                    },
                    unit_amount: 2000,
                },
                quantity: 1,
            }],
            mode: 'payment',
            success_url: `${req.headers.origin}/success.html`,
            cancel_url: `${req.headers.origin}/cancel.html`,
        });
        res.json({ id: session.id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

module.exports = { createCheckoutSession };

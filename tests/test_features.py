from phishsentinel.features import header_feats, content_feats

BASE = {"sender": '"PayPal Support" <alerts@secure-pay.example.net>', "reply_to": "help@gmail.com",
        "return_path": "<>", "subject": "Verify now", "spf_domain": "", "dkim_d": "",
        "n_attachments": 0, "text": "", "html": ""}

def test_replyto_mismatch_and_freemail_reply():
    assert header_feats(BASE)["h_replyto"] == 2

def test_link_text_mismatch_and_hidden_text():
    r = {**BASE, "html": '<a href="http://evil.example.org/x">https://paypal.com/login</a>'
                         '<div style="display:none">filler</div>'}
    f = content_feats(r)
    assert f["u_link_text_mismatch"] == 1 and f["x_hidden"] == 1
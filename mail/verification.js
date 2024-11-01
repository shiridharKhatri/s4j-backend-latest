const nodemailer = require("nodemailer");

const verificationMail = async (email, name, code, subject, details) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  try {
    const info = await transporter.sendMail({
      from: `Swipe 4 Jobs <${process.env.EMAIL}>`,
      to: email,
      subject: subject,
      text: "Verification code",
      html: `
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
        <html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" lang="en">
        <head>
        <title></title>
        <meta charset="UTF-8" />
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <!--[if !mso]>-->
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <!--<![endif]-->
        <meta name="x-apple-disable-message-reformatting" content="" />
        <meta content="target-densitydpi=device-dpi" name="viewport" />
        <meta content="true" name="HandheldFriendly" />
        <meta content="width=device-width" name="viewport" />
        <meta name="format-detection" content="telephone=no, date=no, address=no, email=no, url=no" />
        <style type="text/css">
        table {
        border-collapse: separate;
        table-layout: fixed;
        mso-table-lspace: 0pt;
        mso-table-rspace: 0pt
        }
        table td {
        border-collapse: collapse
        }
        .ExternalClass {
        width: 100%
        }
        .ExternalClass,
        .ExternalClass p,
        .ExternalClass span,
        .ExternalClass font,
        .ExternalClass td,
        .ExternalClass div {
        line-height: 100%
        }
        .gmail-mobile-forced-width {
        display: none;
        display: none !important;
        }
        body, a, li, p, h1, h2, h3 {
        -ms-text-size-adjust: 100%;
        -webkit-text-size-adjust: 100%;
        }
        html {
        -webkit-text-size-adjust: none !important
        }
        body, #innerTable {
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale
        }
        #innerTable img+div {
        display: none;
        display: none !important
        }
        img {
        Margin: 0;
        padding: 0;
        -ms-interpolation-mode: bicubic
        }
        h1, h2, h3, p, a {
        line-height: inherit;
        overflow-wrap: normal;
        white-space: normal;
        word-break: break-word
        }
        a {
        text-decoration: none
        }
        h1, h2, h3, p {
        min-width: 100%!important;
        width: 100%!important;
        max-width: 100%!important;
        display: inline-block!important;
        border: 0;
        padding: 0;
        margin: 0
        }
        a[x-apple-data-detectors] {
        color: inherit !important;
        text-decoration: none !important;
        font-size: inherit !important;
        font-family: inherit !important;
        font-weight: inherit !important;
        line-height: inherit !important
        }
        u + #body a {
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
        }
        a[href^="mailto"],
        a[href^="tel"],
        a[href^="sms"] {
        color: inherit;
        text-decoration: none
        }
        </style>
        <style type="text/css">
        @media (min-width: 481px) {
        .hd { display: none!important }
        }
        </style>
        <style type="text/css">
        @media (max-width: 480px) {
        .hm { display: none!important }
        }
        </style>
        <style type="text/css">
        @media (max-width: 480px) {
        .t20,.t27{width:460px!important}.t27{padding-top:20px!important;padding-bottom:20px!important}.t18,.t25,.t35{text-align:center!important}.t17,.t24,.t34{vertical-align:top!important}.t15{padding:30px!important}.t1,.t13,.t5{width:400px!important}.t12,.t39,.t4,.t8{mso-line-height-alt:20px!important;line-height:20px!important}.t7,.t9{line-height:50px!important;mso-text-raise:10px!important}.t9{width:326px!important}.t37{width:480px!important}.t30{width:380px!important}.t11{line-height:23px!important;font-size:16px!important;mso-text-raise:2px!important}
        }
        </style>
        <style type="text/css">@media (max-width: 480px) {[class~="x_t27"]{padding-top:20px!important;padding-bottom:20px!important;width:460px!important;} [class~="x_t25"]{text-align:center!important;} [class~="x_t24"]{vertical-align:top!important;} [class~="x_t20"]{width:460px!important;} [class~="x_t18"]{text-align:center!important;} [class~="x_t17"]{vertical-align:top!important;} [class~="x_t15"]{padding-left:30px!important;padding-top:30px!important;padding-bottom:30px!important;padding-right:30px!important;} [class~="x_t1"]{width:400px!important;} [class~="x_t8"]{mso-line-height-alt:20px!important;line-height:20px!important;} [class~="x_t9"]{width:326px!important;line-height:50px!important;mso-text-raise:10px!important;} [class~="x_t7"]{line-height:50px!important;mso-text-raise:10px!important;} [class~="x_t4"]{mso-line-height-alt:20px!important;line-height:20px!important;} [class~="x_t5"]{width:400px!important;} [class~="x_t39"]{mso-line-height-alt:20px!important;line-height:20px!important;} [class~="x_t37"]{width:480px!important;} [class~="x_t35"]{text-align:center!important;} [class~="x_t34"]{vertical-align:top!important;} [class~="x_t30"]{width:380px!important;} [class~="x_t12"]{mso-line-height-alt:20px!important;line-height:20px!important;} [class~="x_t13"]{width:400px!important;} [class~="x_t11"]{line-height:23px!important;font-size:16px!important;mso-text-raise:2px!important;}}</style>
        <!--[if !mso]>-->
        <link href="https://fonts.googleapis.com/css2?family=Inter+Tight:wght@700&amp;family=Inter:wght@400;500;600&amp;family=Fira+Sans:wght@400&amp;display=swap" rel="stylesheet" type="text/css" />
        <!--<![endif]-->
        <!--[if mso]>
        <xml>
        <o:OfficeDocumentSettings>
        <o:AllowPNG/>
        <o:PixelsPerInch>96</o:PixelsPerInch>
        </o:OfficeDocumentSettings>
        </xml>
        <![endif]-->
        </head>
        <body id="body" class="t42" style="min-width:100%;Margin:0px;padding:0px;background-color:#EDEDED;"><div class="t41" style="background-color:#EDEDED;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" align="center"><tr><td class="t40" style="font-size:0;line-height:0;mso-line-height-rule:exactly;background-color:#EDEDED;" valign="top" align="center">
        <!--[if mso]>
        <v:background xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false">
        <v:fill color="#EDEDED"/>
        </v:background>
        <![endif]-->
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" align="center" id="innerTable"><tr><td align="center">
        <table class="t28" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="600" class="t27" style="padding:26px 10px 26px 10px;">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t27" style="width:580px;padding:26px 10px 26px 10px;">
        <!--<![endif]-->
        <table class="t26" role="presentation" cellpadding="0" cellspacing="0" align="center" valign="top">
        <tr class="t25"><td></td><td class="t24" width="580" valign="top">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t23" style="width:100%;"><tr>
        <td class="t22" style="background-color:transparent;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;"><tr><td align="center">
        <table class="t21" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="580" class="t20">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t20" style="width:580px;">
        <!--<![endif]-->
        <table class="t19" role="presentation" cellpadding="0" cellspacing="0" align="center" valign="top">
        <tr class="t18"><td></td><td class="t17" width="580" valign="top">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t16" style="width:100%;"><tr>
        <td class="t15" style="border-bottom:1px solid #F7F7F7;overflow:hidden;background-color:#FFFFFF;padding:50px 50px 50px 50px;border-radius:0 0 8px 8px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;"><tr><td align="left">
        <table class="t2" role="presentation" cellpadding="0" cellspacing="0" style="Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="480" class="t1">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t1" style="width:480px;">
        <!--<![endif]-->
        <h1 class="t0" style="margin:0;Margin:0;font-family:Inter Tight,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:40px;font-weight:700;font-style:normal;font-size:35px;text-decoration:none;text-transform:none;direction:ltr;color:#850101;text-align:left;mso-line-height-rule:exactly;mso-text-raise:2px;">Email verification code&nbsp;</h1></td>
        </tr></table>
        </td></tr><tr><td><div class="t4" style="mso-line-height-rule:exactly;mso-line-height-alt:30px;line-height:30px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr><tr><td align="left">
        <table class="t6" role="presentation" cellpadding="0" cellspacing="0" style="Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="480" class="t5">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t5" style="width:480px;">
        <!--<![endif]-->
        <p class="t3" style="margin:0;Margin:0;font-family:Inter,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:28px;font-weight:500;font-style:normal;font-size:21px;text-decoration:none;text-transform:none;direction:ltr;color:#333333;text-align:left;mso-line-height-rule:exactly;mso-text-raise:2px;">${details}</p></td>
        </tr></table>
        </td></tr><tr><td><div class="t8" style="mso-line-height-rule:exactly;mso-line-height-alt:30px;line-height:30px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr><tr><td align="left">
        <table class="t10" role="presentation" cellpadding="0" cellspacing="0" style="Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="260" class="t9" style="background-color:#850101;overflow:hidden;text-align:center;line-height:60px;mso-line-height-rule:exactly;mso-text-raise:13px;border-radius:14px 14px 14px 14px;">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t9" style="background-color:#850101;overflow:hidden;width:260px;text-align:center;line-height:60px;mso-line-height-rule:exactly;mso-text-raise:13px;border-radius:14px 14px 14px 14px;">
        <!--<![endif]-->
        <a class="t7" href="#" style="display:block;margin:0;Margin:0;font-family:Inter,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:60px;font-weight:600;font-style:normal;font-size:18px;text-decoration:none;direction:ltr;color:#FFFFFF;text-align:center;mso-line-height-rule:exactly;mso-text-raise:13px;" target="_blank">${code}</a></td>
        </tr></table>
        </td></tr><tr><td><div class="t12" style="mso-line-height-rule:exactly;mso-line-height-alt:30px;line-height:30px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr><tr><td align="left">
        <table class="t14" role="presentation" cellpadding="0" cellspacing="0" style="Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="480" class="t13">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t13" style="width:480px;">
        <!--<![endif]-->
        <p class="t11" style="margin:0;Margin:0;font-family:Inter,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:27px;font-weight:400;font-style:normal;font-size:18px;text-decoration:none;text-transform:none;direction:ltr;color:#545454;text-align:left;mso-line-height-rule:exactly;mso-text-raise:3px;">If you do not want to verify your account or didn&#39;t request , you can ignore and delete this email.</p></td>
        </tr></table>
        </td></tr></table></td>
        </tr></table>
        </td>
        <td></td></tr>
        </table></td>
        </tr></table>
        </td></tr></table></td>
        </tr></table>
        </td>
        <td></td></tr>
        </table></td>
        </tr></table>
        </td></tr><tr><td align="center">
        <table class="t38" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="600" class="t37">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t37" style="width:600px;">
        <!--<![endif]-->
        <table class="t36" role="presentation" cellpadding="0" cellspacing="0" align="center" valign="top">
        <tr class="t35"><td></td><td class="t34" width="600" valign="top">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t33" style="width:100%;"><tr>
        <td class="t32" style="padding:0 50px 0 50px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;"><tr><td align="left">
        <table class="t31" role="presentation" cellpadding="0" cellspacing="0" style="Margin-right:auto;">
        <tr>
        <!--[if mso]>
        <td width="420" class="t30">
        <![endif]-->
        <!--[if !mso]>-->
        <td class="t30" style="width:420px;">
        <!--<![endif]-->
        <p class="t29" style="margin:0;Margin:0;font-family:Fira Sans,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:23px;font-weight:400;font-style:normal;font-size:14px;text-decoration:none;text-transform:none;direction:ltr;color:#878787;text-align:left;mso-line-height-rule:exactly;mso-text-raise:3px;">© 2022 Swipe 4 Jobs . All Rights Reserved<br/></p></td>
        </tr></table>
        </td></tr></table></td>
        </tr></table>
        </td>
        <td></td></tr>
        </table></td>
        </tr></table>
        </td></tr><tr><td><div class="t39" style="mso-line-height-rule:exactly;mso-line-height-alt:50px;line-height:50px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr></table></td></tr></table></div><div class="gmail-mobile-forced-width" style="white-space: nowrap; font: 15px courier; line-height: 0;">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;
        </div></body>
        </html>
        `,
    });
  } catch (error) {
    console.error("Error sending email:", error);
  }
};

module.exports = verificationMail;

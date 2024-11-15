const express = require("express");
const Payment = require("../models/Payment");
const Stripe = require("stripe");
const userAccess = require("../middleware/userAccess");
const User = require("../models/User");
const adminAccess = require("../middleware/adminAccess");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const routes = express.Router();
const Admin = require("../models/Admin");
routes.post("/buy/search/limit/:type", userAccess, async (req, res) => {
  let user = await User.findById(req.user.id);
  if (!user) {
    return res
      .status(404)
      .json({ success: false, message: "User not found with given id" });
  }

  const { qty, amt, name } = req.body;
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    line_items: [
      {
        price_data: {
          currency: "usd",
          product_data: {
            name: name,
          },
          unit_amount: Math.round(amt * 100),
        },
        quantity: qty,
      },
    ],
    mode: "payment",
    success_url: `${process.env.FRONTEND_URL}/status/success/${process.env.SUCCESS_ID}`,
    cancel_url: `${process.env.FRONTEND_URL}/status/cancel/${process.env.CANCEL_ID}`,
    payment_intent_data: {
      description: `Payment for Additional ${req.params.type} Limit`,
      metadata: {
        userId: req.user.id,
        serviceType: req.params.type,
        quantity: qty,
      },
    },
    metadata: {
      userId: req.user.id,
      serviceType: req.params.type,
      quantity: qty,
    },
  });
  res.status(200).json({ id: session.id });
});

routes.post(
  "/webhook",
  express.json({ type: "application/json" }),
  async (req, res) => {
    const event = req.body;
    if (event.type === "checkout.session.completed") {
      let metaDataObj = event.data.object.metadata;
      let user = await User.findById(metaDataObj.userId);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found with given id" });
      }
      const quantity = Number(metaDataObj.quantity);
      if (isNaN(quantity)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid quantity value" });
      }
      if (metaDataObj.serviceType === "search") {
        await User.findByIdAndUpdate(
          metaDataObj.userId,
          {
            $set: {
              search_limit: user.search_limit + Number(quantity),
            },
          },
          { new: true }
        );
      } else if (metaDataObj.serviceType === "job_posting") {
        await User.findByIdAndUpdate(
          metaDataObj.userId,
          {
            $set: {
              posting_limit: user.posting_limit + Number(quantity),
            },
          },
          { new: true }
        );
      }

      await Payment.create({
        userId: metaDataObj.userId,
        payment_id: `${user.name.trim().split(" ")[0][0].toUpperCase()}_${
          Math.floor(Math.random() * 90000000) + 10000000
        }`,
        transactionId: event.data.object.id,
        amount: event.data.object.amount_total / 100,
        paymentStatus: event.data.object.status,
        serviceType: metaDataObj.serviceType,
        search_limit: metaDataObj.quantity,
        remarks:
          metaDataObj.serviceType === "search"
            ? `Purhcased search limit of ${metaDataObj.quantity} qty`
            : `Purhcased post limit of ${metaDataObj.quantity} qty`,
      });

      return res
        .status(200)
        .json({ success: true, message: "Purchase successfully" });
    }
  }
);

routes.post("/details/fetch", adminAccess, async (req, res) => {
  try {
    let adminId = req.admin.id;
    let admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "You don't have access to this end points",
      });
    }
    let payment = await Payment.find();
    if (!payment) {
      return res
        .status(404)
        .json({ success: false, message: "No payment records has been found" });
    }
    let data = [];
    for (const elems of payment) {
      let user = await User.findById(elems.userId);
      if (user) {
        data.push({
          id: elems.id,
          userId: user.id,
          name: user.name,
          email: user.email,
          paymentId: elems.id,
          transId: elems.transactionId,
          paymentMethod: elems.paymentMethod,
          amount: elems.amount,
          currency: elems.currency,
          paymentStatus: elems.paymentStatus,
          serviceType: elems.serviceType,
          search_limit: elems.search_limit,
          remarks: elems.remarks,
          paymentDate: elems.paymentDate,
        });
      }
    }
    return res.status(200).json({ success: true, data });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, type: "server", message: error.message });
  }
});

routes.get("/details/history/:id", userAccess, async (req, res) => {
  try {
    const { id } = req.params;
    if (String(id) !== String(req.user.id)) {
      return res
        .status(401)
        .json({ success: false, message: "Id doesn't match" });
    }
    let paymentDetails = await Payment.find({ userId: req.user.id });
    let user = await User.findById(req.user.id).select("-password");
    if (!paymentDetails) {
      return res
        .status(404)
        .json({ success: false, message: "No payment has been made till now" });
    }
    res.status(200).json({
      success: true,
      data: paymentDetails,
      user: {
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});
module.exports = routes;

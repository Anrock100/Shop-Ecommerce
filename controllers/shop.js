const fs = require('fs');
const path = require('path');

const PDFDocument = require('pdfkit');

const Product = require('../models/product');
const Order = require('../models/order');

const ITEMS_PER_PAGE = 1;

exports.getProducts = (req, res, next) => {
  Product.find()
    .then((products) => {
      res.render('shop/product-list', {
        prods: products,
        pageTitle: 'All Products',
        path: '/products',
      });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.getProduct = (req, res, next) => {
  const prodId = req.params.productId;
  Product.findById(prodId)
    .then((product) => {
      res.render('shop/product-detail', {
        product: product,
        pageTitle: product.title,
        path: '/products',
      });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.getIndex = (req, res, next) => {
  const page = +req.query.page || 1;
  let totalItems;

  Product.find()
    .countDocuments()
    .then((numProducts) => {
      totalItems = numProducts;
      return Product.find()
        .skip((page - 1) * ITEMS_PER_PAGE)
        .limit(ITEMS_PER_PAGE);
    })
    .then((products) => {
      res.render('shop/index', {
        prods: products,
        pageTitle: 'Shop',
        path: '/',
        currentPage: page,
        hasNextPage: ITEMS_PER_PAGE * page < totalItems,
        hasPreviousPage: page > 1,
        nextPage: page + 1,
        previousPage: page - 1,
        lastPage: Math.ceil(totalItems / ITEMS_PER_PAGE),
      });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

// exports.getIndex = async (req, res, next) => {
//   const page = req.query.page;
//   let totalItems;

//   totalItems = await Product.find().countDocuments();

//   const products = await Product.find()
//     .skip((page - 1) * ITEMS_PER_PAGE)
//     .limit(ITEMS_PER_PAGE);

//   res.render('shop/index', {
//     prods: products,
//     pageTitle: 'Shop',
//     path: '/',
//     totalProducts: totalItems,
//     hasNextPage: ITEMS_PER_PAGE * page < totalItems,
//     hasPreviousPage: page > 1,
//     nextPage: page + 1,
//     previousPage: page - 1,
//     lastPage: Math.ceil(totalItems / ITEMS_PER_PAGE),
//   });
// };

// exports.getCart = (req, res, next) => {
//   req.user
//     .populate('cart.items.productId')
//     .then((user) => {
//       let totalPrice = 0;
//       user.cart.items.forEach((item) => {
//         totalPrice += item.productId.price * item.quantity;
//       });
//       const products = user.cart.items;

//       res.render('shop/cart', {
//         path: '/cart',
//         pageTitle: 'Your Cart',
//         products: products,
//         totalPrice,
//
//       });
//     })
//     .catch((err) => console.log(err));
// };

//new method

exports.getCart = async (req, res, next) => {
  let totalPrice = 0;
  const user = await req.user.populate('cart.items.productId');

  user.cart.items.forEach((item) => {
    totalPrice += item.productId.price * item.quantity;
  });

  const products = user.cart.items;

  res.render('shop/cart', {
    path: '/cart',
    pageTitle: 'Your Cart',
    products: products,
    totalPrice,
  });
};

exports.postCart = (req, res, next) => {
  const prodId = req.body.productId;
  Product.findById(prodId)
    .then((product) => {
      return req.user.addToCart(product);
    })
    .then((result) => {
      res.redirect('/cart');
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postCartDeleteProduct = (req, res, next) => {
  const prodId = req.body.productId;
  req.user
    .removeFromCart(prodId)
    .then((result) => {
      res.redirect('/cart');
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postOrder = (req, res, next) => {
  req.user
    .populate('cart.items.productId')
    .then((user) => {
      const products = user.cart.items.map((item) => {
        return {
          quantity: item.quantity,
          product: { ...item.productId._doc }, //this is the metadata that mongoose attaches (ATTENTION)
        };
      });
      const order = new Order({
        user: {
          email: req.user.email,
          userId: req.user,
        },
        products: products,
      });

      return order.save();
    })
    .then((result) => {
      return req.user.clearCart();
    })
    .then((result) => {
      res.redirect('/orders');
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.getOrders = (req, res, next) => {
  Order.find({ 'user.userId': req.user._id })
    .then((orders) => {
      //adding total price
      let totalPrice = 0;
      orders.forEach((order) => {
        let oneOrderPrice = 0;
        order.products.forEach((product) => {
          oneOrderPrice += product.quantity * product.product.price;
        });
        totalPrice += oneOrderPrice;
      });
      res.render('shop/orders', {
        path: '/orders',
        pageTitle: 'Your Orders',
        orders: orders,
        totalPrice,
      });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

//my removeOrder
exports.removeOrder = async (req, res, next) => {
  const orderId = req.params.orderId;
  await Order.deleteOne({ _id: orderId });

  Order.find({ 'user.userId': req.user._id })
    .then((orders) => {
      //adding total price
      let totalPrice = 0;
      orders.forEach((order) => {
        let oneOrderPrice = 0;
        order.products.forEach((product) => {
          oneOrderPrice += product.quantity * product.product.price;
        });
        totalPrice += oneOrderPrice;
      });
      res.render('shop/orders', {
        path: '/orders',
        pageTitle: 'Your Orders',
        orders: orders,
        totalPrice,
      });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.getInvoice = (req, res, next) => {
  const orderId = req.params.orderId;
  Order.findById(orderId)
    .then((order) => {
      if (!order) {
        return next(new Error('No order found.'));
      }
      if (order.user.userId.toString() !== req.user._id.toString()) {
        return next(new Error('Unauthorized'));
      }
      const invoiceName = 'invoice-' + orderId + '.pdf';
      const invoicePath = path.join('data', 'invoices', invoiceName);

      const pdfDoc = new PDFDocument();
      // res.setHeader('Content-Type', 'application/pdf');
      // res.setHeader(
      //   'Content-Disposition',
      //   'inline;filename="' + invoiceName + '"'
      // );

      pdfDoc.pipe(fs.createWriteStream(invoicePath)); //pdfdoc is a readable stream
      pdfDoc.pipe(res);

      pdfDoc.fontSize(26).text('Invoice', {
        underline: true,
      });
      pdfDoc.text('---------------');
      let totalPrice = 0;
      order.products.forEach((prod) => {
        totalPrice += prod.quantity * prod.product.price;
        pdfDoc
          .fillColor('green')
          .fontSize(17)
          .text(
            prod.product.title +
              ' - ' +
              prod.quantity +
              ' * ' +
              'Rs.' +
              prod.product.price
          );
      });

      pdfDoc.text('------');
      pdfDoc.text('Total Price: Rs.' + totalPrice);

      pdfDoc.end();

      // fs.readFile(invoicePath, (err, data) => {
      //   if (err) {
      //     return next(err);
      //   }
      //   res.setHeader('Content-Type', 'application/pdf');
      //   res.setHeader('Content-Disposition', 'inline');
      //   res.send(data);
      // });
      // const file = fs.createReadStream(invoicePath);
      // file.pipe(res);
    })
    .catch((err) => next(err));
};

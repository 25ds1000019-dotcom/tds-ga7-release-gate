'use strict';

const { evaluateReleaseGate } = require('../policy');

module.exports = function releaseGate(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ decision: 'block', violations: ['TESTS_INCOMPLETE'] });
    return;
  }
  res.status(200).json(evaluateReleaseGate(req.body));
};

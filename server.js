const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dns = require('dns').promises;

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public')); // Serve frontend from public folder

// Helper function to extract domain from email
const getDomain = (email) => {
  const parts = email.split('@');
  return parts.length === 2 ? parts[1].toLowerCase() : null;
};

// Functions to check SPF, DKIM, and DMARC DNS records
async function checkSPF(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const spfFound = records.some(record => record.join('').toLowerCase().includes('v=spf1'));
    console.log(`SPF records for ${domain}:`, records);
    console.log('SPF valid:', spfFound);
    return spfFound;
  } catch (err) {
    console.log(`Could not find SPF record for domain ${domain}:`, err.message);
    return false;
  }
}

async function checkDKIM(domain) {
  const selector = 'default'; // Default DKIM selector, adjust if needed
  const dkimDomain = `${selector}._domainkey.${domain}`;
  try {
    const records = await dns.resolveTxt(dkimDomain);
    const dkimValid = records.length > 0;
    console.log(`DKIM records for ${dkimDomain}:`, records);
    console.log('DKIM valid:', dkimValid);
    return dkimValid;
  } catch (err) {
    console.log(`Could not find DKIM record for domain ${dkimDomain}:`, err.message);
    return false;
  }
}

async function checkDMARC(domain) {
  const dmarcDomain = `_dmarc.${domain}`;
  try {
    const records = await dns.resolveTxt(dmarcDomain);
    const dmarcValid = records.length > 0;
    console.log(`DMARC records for ${dmarcDomain}:`, records);
    console.log('DMARC valid:', dmarcValid);
    return dmarcValid;
  } catch (err) {
    console.log(`Could not find DMARC record for domain ${dmarcDomain}:`, err.message);
    return false;
  }
}

// POST /check-email endpoint with enhanced checks
app.post('/check-email', async (req, res) => {
  const { from, returnPath } = req.body;

  if (!from || !returnPath) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }

  const fromDomain = getDomain(from);
  const returnPathDomain = getDomain(returnPath);

  if (!fromDomain || !returnPathDomain) {
    return res.status(400).json({ message: 'Invalid email format.' });
  }

  // Basic domain matching check
  if (fromDomain !== returnPathDomain) {
    return res.status(200).json({
      result: 'Suspicious',
      message: 'From and Return-Path domains do not match.'
    });
  }

  try {
    // Check authentication DNS records in parallel
    const [spfValid, dkimValid, dmarcValid] = await Promise.all([
      checkSPF(fromDomain),
      checkDKIM(fromDomain),
      checkDMARC(fromDomain)
    ]);

    // Compose message and result based on checks
    let message = 'Email authenticity checks: ';
    let issues = 0;

    if (!spfValid) {
      message += 'SPF missing or invalid; ';
      issues++;
    }
    if (!dkimValid) {
      message += 'DKIM missing or invalid; ';
    }
    if (!dmarcValid) {
      message += 'DMARC missing or invalid; ';
      issues++;
    }

    const result = issues > 0 ? 'Suspicious' : 'Legitimate';
    if (issues === 0) {
      message = 'Email appears to be legitimate with proper SPF, DKIM, and DMARC.';
    }

    // Add helpful links to external DNS tools for manual verification
    message += '\n\nFor manual checks use external tools:\n' +
      '- SPF: https://mxtoolbox.com/spf.aspx\n' +
      '- DKIM: https://dkimvalidator.com/\n' +
      '- DMARC: https://dmarcian.com/dmarc-inspector/';

    return res.status(200).json({ result, message });
  } catch (err) {
    console.error('DNS lookup error:', err);
    return res.status(500).json({ message: 'Error while checking DNS records.' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

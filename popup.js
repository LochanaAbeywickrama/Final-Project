document.getElementById('detectButton').addEventListener('click', function() {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      const currentUrl = tabs[0].url;
      checkURL(currentUrl);
    });
  });
  
  function checkURL(url) {
    fetch('https://phishingbadge-o2qd.onrender.com/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
      const resultMessage = document.getElementById('resultMessage');
      if (data.phishing) {
        resultMessage.textContent = `Phishing detected: ${url}`;
        resultMessage.style.color = 'red';
      } else {
        resultMessage.textContent = `Legitimate site: ${url}`;
        resultMessage.style.color = 'green';
      }
    })
    .catch(error => {
      console.error('Error:', error);
      document.getElementById('resultMessage').textContent = 'Error checking the URL.';
    });
  }
  
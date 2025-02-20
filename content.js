function detectURLs() {
  const links = document.querySelectorAll('a');
  links.forEach(link => {
    const url = link.href;
    if (url) {
      fetch('https://phishingurldetector.onrender.com/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      })
      .then(response => response.json())
      .then(data => {
        if (data.phishing) {
          console.log(`Phishing detected: ${url}`);
        } else {
          console.log(`Legitimate site: ${url}`);
        }
      })
      .catch(error => console.error('Error:', error));
    }
  });
}

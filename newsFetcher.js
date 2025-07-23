const axios = require('axios');

// Function to fetch news from NewsData.io
async function fetchNewsDataIo(apiKey, query = '', category = '') {
    try {
        let url = `https://newsdata.io/api/1/news?apikey=${apiKey}&language=en`;
        if (query) url += `&q=${encodeURIComponent(query)}`;
        if (category) url += `&category=${encodeURIComponent(category)}`;

        const response = await axios.get(url);
        return response.data.results.map(article => ({
            title: article.title,
            link: article.link,
            description: article.description,
            source: article.source_id,
            pubDate: article.pubDate
        }));
    } catch (error) {
        console.error('Error fetching from NewsData.io:', error.message);
        return [];
    }
}

// Function to fetch news from NewsAPI.org
async function fetchNewsApiOrg(apiKey, source = '', query = '') {
    try {
        let url = `https://newsapi.org/v2/top-headlines?apiKey=${apiKey}&language=en`;
        if (source) url += `&sources=${encodeURIComponent(source)}`;
        if (query) url += `&q=${encodeURIComponent(query)}`;

        const response = await axios.get(url);
        return response.data.articles.map(article => ({
            title: article.title,
            link: article.url,
            description: article.description,
            source: article.source.name,
            pubDate: article.publishedAt
        }));
    } catch (error) {
        console.error('Error fetching from NewsAPI.org:', error.message);
        return [];
    }
}

module.exports = {
    fetchNewsDataIo,
    fetchNewsApiOrg
};
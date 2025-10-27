import React, { useState, useEffect } from 'react';
import { 
  FiGithub, 
  FiLinkedin, 
  FiMail, 
  FiShield, 
  FiZap, 
  FiActivity,
  FiServer,
  FiCode,
  FiLock,
  FiArrowRight
} from 'react-icons/fi';
import { motion } from 'framer-motion';
import Navbar from '../components/Navbar';

const LandingPage = () => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  const fadeInUp = {
    initial: { opacity: 0, y: 60 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.6 }
  };

  const staggerContainer = {
    animate: {
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const features = [
    {
      icon: <FiShield className="w-8 h-8" />,
      title: "AI-based Threat Detection",
      description: "Advanced machine learning models detect and prevent sophisticated API attacks in real-time."
    },
    {
      icon: <FiZap className="w-8 h-8" />,
      title: "Real-time IP Blocking",
      description: "Automatically block malicious IP addresses and suspicious traffic patterns instantly."
    },
    {
      icon: <FiActivity className="w-8 h-8" />,
      title: "Custom Dashboard",
      description: "Comprehensive monitoring and analytics dashboard for complete API security visibility."
    },
    {
      icon: <FiServer className="w-8 h-8" />,
      title: "Lightweight & Scalable",
      description: "High-performance architecture designed to handle millions of requests with minimal latency."
    },
    {
      icon: <FiCode className="w-8 h-8" />,
      title: "Open Source & Self-Hosted",
      description: "Full control over your security infrastructure with complete transparency and customization."
    },
    {
      icon: <FiLock className="w-8 h-8" />,
      title: "DDoS, Bot & Injection Protection",
      description: "Multi-layered protection against DDoS attacks, malicious bots, and SQL injection attempts."
    }
  ];

  const technologies = [
    { name: "React", logo: "⚛️" },
    { name: "FastAPI", logo: "🚀" },
    { name: "PostgreSQL", logo: "🐘" },
    { name: "LightGBM", logo: "💡" },
    { name: "Docker", logo: "🐳" },
    { name: "Nginx", logo: "🌐" },
    { name: "JWT", logo: "🔑" }
  ];

  const architectureSteps = [
    { name: "Client", description: "API requests from web/mobile applications" },
    { name: "TLS", description: "SSL/TLS termination and encryption" },
    { name: "Load Balancer", description: "Traffic distribution across multiple instances" },
    { name: "AI Gateway", description: "AI-powered threat detection and analysis" },
    { name: "Backend Services", description: "Your protected API endpoints" }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-white text-gray-800">
      {/* Navbar */}
      <nav className="fixed top-0 w-full z-50 backdrop-blur-md bg-white/80 border-b border-gray-200">
        <div className="container mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-cyan-500 bg-clip-text text-transparent"
            >
              AI Gateway
            </motion.div>
            <div className="hidden md:flex space-x-8">
              {['Home', 'Features', 'Architecture', 'Demo', 'Contact'].map((item) => (
                <a
                  key={item}
                  href={`#${item.toLowerCase()}`}
                  className="text-gray-600 hover:text-blue-600 transition-colors duration-300 font-medium"
                >
                  {item}
                </a>
              ))}
            </div>
          </div>
        </div>
      </nav>


      {/* Hero Section */}
      <section id="home" className="pt-32 pb-20 px-6">
        <div className="container mx-auto">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <motion.div
              initial="initial"
              animate="animate"
              variants={staggerContainer}
            >
              <motion.h1 
                variants={fadeInUp}
                className="text-5xl lg:text-6xl font-bold leading-tight text-gray-900"
              >
                Secure Your APIs with{" "}
                <span className="bg-gradient-to-r from-blue-600 to-cyan-500 bg-clip-text text-transparent">
                  AI Intelligence
                </span>
              </motion.h1>
              <motion.p 
                variants={fadeInUp}
                className="text-xl text-gray-600 mt-6 mb-8 leading-relaxed"
              >
                A self-hosted, AI-enhanced API gateway that detects, blocks, and monitors cyber threats in real time.
              </motion.p>
              <motion.div 
                variants={fadeInUp}
                className="flex flex-col sm:flex-row gap-4"
              >
                <button className="bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-700 hover:to-cyan-600 text-white px-8 py-4 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-blue-500/25">
                  Try Demo
                </button>
                <button className="border border-gray-300 hover:border-cyan-500 text-gray-700 hover:text-cyan-600 px-8 py-4 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 bg-white">
                  <div className="flex items-center justify-center gap-2">
                    <FiGithub className="w-5 h-5" />
                    View on GitHub
                  </div>
                </button>
              </motion.div>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8 }}
              className="relative"
            >
              <div className="w-full h-96 bg-gradient-to-br from-blue-50 to-cyan-50 rounded-2xl border border-gray-200 backdrop-blur-sm flex items-center justify-center shadow-lg">
                <div className="text-center">
                  <div className="w-20 h-20 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-full mx-auto mb-4 flex items-center justify-center shadow-lg">
                    <FiShield className="w-10 h-10 text-white" />
                  </div>
                  <p className="text-gray-600 font-medium">AI Gateway Visualization</p>
                </div>
              </div>
              <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-2xl blur opacity-10"></div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-6 bg-gray-50/50">
        <div className="container mx-auto">
          <motion.div
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
            variants={staggerContainer}
            className="text-center mb-16"
          >
            <motion.h2 
              variants={fadeInUp}
              className="text-4xl font-bold mb-4 text-gray-900"
            >
              Why Choose Our Gateway?
            </motion.h2>
            <motion.p 
              variants={fadeInUp}
              className="text-xl text-gray-600 max-w-2xl mx-auto"
            >
              Enterprise-grade security features powered by artificial intelligence
            </motion.p>
          </motion.div>

          <motion.div
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
            variants={staggerContainer}
            className="grid md:grid-cols-2 lg:grid-cols-3 gap-8"
          >
            {features.map((feature, index) => (
              <motion.div
                key={index}
                variants={fadeInUp}
                className="bg-white backdrop-blur-sm border border-gray-200 rounded-xl p-6 hover:border-cyan-500 transition-all duration-300 transform hover:-translate-y-2 hover:shadow-2xl hover:shadow-cyan-500/10 group"
              >
                <div className="text-cyan-600 mb-4 group-hover:scale-110 transition-transform duration-300">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-semibold mb-3 text-gray-900">{feature.title}</h3>
                <p className="text-gray-600 leading-relaxed">{feature.description}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Architecture Section */}
      <section id="architecture" className="py-20 px-6">
        <div className="container mx-auto">
          <motion.div
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
            variants={staggerContainer}
            className="text-center mb-16"
          >
            <motion.h2 
              variants={fadeInUp}
              className="text-4xl font-bold mb-4 text-gray-900"
            >
              High-Level Architecture
            </motion.h2>
          </motion.div>

          <motion.div
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
            className="flex flex-col lg:flex-row items-center justify-between gap-8"
          >
            {architectureSteps.map((step, index) => (
              <React.Fragment key={index}>
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.2 }}
                  viewport={{ once: true }}
                  className="text-center flex-1"
                >
                  <div className="bg-gradient-to-br from-blue-600 to-cyan-500 p-6 rounded-xl shadow-lg mb-4 text-white">
                    <h3 className="text-lg font-semibold">{step.name}</h3>
                  </div>
                  <p className="text-gray-600 text-sm">{step.description}</p>
                </motion.div>
                {index < architectureSteps.length - 1 && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    whileInView={{ opacity: 1 }}
                    transition={{ delay: index * 0.2 + 0.1 }}
                    viewport={{ once: true }}
                    className="hidden lg:block"
                  >
                    <FiArrowRight className="w-8 h-8 text-cyan-500" />
                  </motion.div>
                )}
              </React.Fragment>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Tech Stack Section */}
      <section className="py-20 px-6 bg-gray-50/50">
        <div className="container mx-auto">
          <motion.div
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
            variants={staggerContainer}
            className="text-center mb-16"
          >
            <motion.h2 
              variants={fadeInUp}
              className="text-4xl font-bold mb-4 text-gray-900"
            >
              Built with Modern Technologies
            </motion.h2>
          </motion.div>

          <motion.div
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
            variants={staggerContainer}
            className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-8"
          >
            {technologies.map((tech, index) => (
              <motion.div
                key={index}
                variants={fadeInUp}
                className="text-center group"
              >
                <div className="bg-white backdrop-blur-sm border border-gray-200 rounded-xl p-6 hover:border-cyan-500 transition-all duration-300 transform hover:scale-110 group-hover:shadow-lg group-hover:shadow-cyan-500/20">
                  <div className="text-4xl mb-2">{tech.logo}</div>
                  <h3 className="font-semibold text-gray-700">{tech.name}</h3>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Demo Section */}
      <section id="demo" className="py-20 px-6">
        <div className="container mx-auto">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <motion.div
              initial={{ opacity: 0, x: -50 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
            >
              <h2 className="text-4xl font-bold mb-6 text-gray-900">
                Monitor, Block, and Analyze API Traffic in Real Time
              </h2>
              <p className="text-xl text-gray-600 mb-8 leading-relaxed">
                Our intuitive dashboard provides comprehensive visibility into your API security posture, 
                with real-time threat detection, detailed analytics, and instant response capabilities.
              </p>
              <button className="bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-700 hover:to-cyan-600 text-white px-8 py-4 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg">
                Explore Dashboard
              </button>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              className="relative"
            >
              <div className="bg-white border border-gray-200 rounded-2xl p-8 backdrop-blur-sm shadow-lg">
                <div className="bg-gray-100 h-64 rounded-lg flex items-center justify-center mb-6 border border-gray-200">
                  <div className="text-center">
                    <div className="w-16 h-16 bg-cyan-500 rounded-full mx-auto mb-4 flex items-center justify-center shadow-md">
                      <FiActivity className="w-8 h-8 text-white" />
                    </div>
                    <p className="text-gray-600 font-medium">Live Dashboard Preview</p>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-gray-200 h-4 rounded"></div>
                  <div className="bg-gray-200 h-4 rounded"></div>
                  <div className="bg-cyan-500 h-4 rounded"></div>
                </div>
              </div>
              <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-2xl blur opacity-10"></div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact" className="py-20 px-6 bg-gray-50/50">
        <div className="container mx-auto max-w-4xl">
          <motion.div
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
            variants={staggerContainer}
            className="text-center mb-16"
          >
            <motion.h2 
              variants={fadeInUp}
              className="text-4xl font-bold mb-4 text-gray-900"
            >
              Get in Touch
            </motion.h2>
            <motion.p 
              variants={fadeInUp}
              className="text-xl text-gray-600"
            >
              Ready to secure your APIs? Contact us for a demo or consultation.
            </motion.p>
          </motion.div>

          <motion.form
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="bg-white backdrop-blur-sm border border-gray-200 rounded-2xl p-8 shadow-lg"
          >
            <div className="grid md:grid-cols-2 gap-6 mb-6">
              <div>
                <label className="block text-gray-700 mb-2 font-medium">Name</label>
                <input 
                  type="text" 
                  className="w-full bg-gray-50 border border-gray-300 rounded-lg px-4 py-3 text-gray-800 focus:outline-none focus:border-cyan-500 transition-colors"
                  placeholder="Your name"
                />
              </div>
              <div>
                <label className="block text-gray-700 mb-2 font-medium">Email</label>
                <input 
                  type="email" 
                  className="w-full bg-gray-50 border border-gray-300 rounded-lg px-4 py-3 text-gray-800 focus:outline-none focus:border-cyan-500 transition-colors"
                  placeholder="your.email@example.com"
                />
              </div>
            </div>
            <div className="mb-6">
              <label className="block text-gray-700 mb-2 font-medium">Message</label>
              <textarea 
                rows="5"
                className="w-full bg-gray-50 border border-gray-300 rounded-lg px-4 py-3 text-gray-800 focus:outline-none focus:border-cyan-500 transition-colors"
                placeholder="Tell us about your API security needs..."
              ></textarea>
            </div>
            <button 
              type="submit"
              className="bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-700 hover:to-cyan-600 text-white px-8 py-4 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 w-full shadow-lg"
            >
              Send Message
            </button>
          </motion.form>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-6 border-t border-gray-200 bg-white">
        <div className="container mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="text-gray-600 mb-4 md:mb-0">
              © 2025 AI Gateway. All rights reserved.
            </div>
            <div className="flex space-x-6">
              <a href="#" className="text-gray-500 hover:text-cyan-600 transition-colors">
                <FiGithub className="w-6 h-6" />
              </a>
              <a href="#" className="text-gray-500 hover:text-cyan-600 transition-colors">
                <FiLinkedin className="w-6 h-6" />
              </a>
              <a href="#" className="text-gray-500 hover:text-cyan-600 transition-colors">
                <FiMail className="w-6 h-6" />
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
import React from 'react';
import { FaTachometerAlt, FaHome, FaBook, FaQuestionCircle, FaInfoCircle, FaCog } from 'react-icons/fa';

const Sidebar = () => {
  return (
    <aside className="bg-gradient-to-b from-purple-800 to-purple-500 text-white w-60 h-screen p-6 flex flex-col justify-between">
      <div>
        <h1 className="text-2xl font-bold mb-8">Counsel.ai</h1>
        <nav className="space-y-6">
          <a href="/" className="flex items-center py-2 text-lg">
            <FaTachometerAlt className="mr-4" /> Dashboard
          </a>
          <a href="/" className="flex items-center py-2 text-lg">
            <FaHome className="mr-4" /> Home
          </a>
          <a href="/" className="flex items-center py-2 text-lg">
            <FaBook className="mr-4" /> Resources
          </a>
          <a href="/" className="flex items-center py-2 text-lg">
            <FaQuestionCircle className="mr-4" /> How this works
          </a>
          <a href="/" className="flex items-center py-2 text-lg">
            <FaInfoCircle className="mr-4" /> About
          </a>
        </nav>
      </div>

      <div className="mt-8">
        <a href="/" className="flex items-center justify-center py-2 border-2 border-white text-lg bg-purple-600 rounded-lg">
          <FaCog className="mr-2" /> Settings
        </a>
      </div>
    </aside>
  );
};

export default Sidebar;

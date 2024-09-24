import React from 'react';
import { FiBell, FiMessageCircle } from 'react-icons/fi';

const Navbar = () => {
  return (
    <nav className="bg-white shadow-md p-4 flex justify-between items-center">
      <div className="text-xl font-semibold">Dashboard</div>
      <div className="flex items-center space-x-6">
        <div className="flex items-center space-x-4 text-black">
          <FiBell size={24} className="cursor-pointer" />
          <FiMessageCircle size={24} className="cursor-pointer" />
        </div>
        
        <span className="text-gray-500">Aditya</span>
        <div className="w-10 h-10 rounded-full bg-purple-300 flex items-center justify-center">
          <img src="https://via.placeholder.com/150" alt="profile" className="rounded-full" />
        </div>
      </div>
    </nav>
  );
};

export default Navbar;

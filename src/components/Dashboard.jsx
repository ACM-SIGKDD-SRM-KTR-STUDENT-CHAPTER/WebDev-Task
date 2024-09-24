import React from 'react';
import { FaChartLine, FaUserTie, FaBrain, FaRegCheckCircle, FaUserGraduate } from 'react-icons/fa'; 

const Dashboard = () => {
  return (
    <div className="flex-1 p-8 bg-gray-100 min-h-screen">
      <div className="flex space-x-8 mb-8">
        <button className="px-4 py-2 bg-white rounded-lg shadow-sm">Roadmap</button>
        <button className="px-4 py-2 bg-white rounded-lg shadow-sm">My Data</button>
        <button className="px-4 py-2 bg-white rounded-lg shadow-sm">Edit Profile</button>
      </div>

      <div className="grid grid-cols-5 gap-4 mb-8">
        <div className="bg-white rounded-lg p-6 text-center shadow-md">
          <FaChartLine className="text-blue-500 text-3xl mb-2 mx-auto" /> 
          <h2 className="text-gray-500">Aptitude Score</h2>
          <p className="text-2xl font-bold">147</p>
        </div>
        <div className="bg-white rounded-lg p-6 text-center shadow-md">
          <FaUserTie className="text-green-500 text-3xl mb-2 mx-auto" /> 
          <h2 className="text-gray-500">Personality Type</h2>
          <p className="text-2xl font-bold">INTJ</p>
        </div>
        <div className="bg-white rounded-lg p-6 text-center shadow-md">
          <FaBrain className="text-purple-500 text-3xl mb-2 mx-auto" /> 
          <h2 className="text-gray-500">Learning Type</h2>
          <p className="text-2xl font-bold">Visual</p>
        </div>
        <div className="bg-white rounded-lg p-6 text-center shadow-md">
          <FaRegCheckCircle className="text-red-500 text-3xl mb-2 mx-auto" /> 
          <h2 className="text-gray-500">Completion</h2>
          <p className="text-2xl font-bold">45%</p>
        </div>
        <div className="bg-white rounded-lg p-6 text-center shadow-md">
          <FaUserGraduate className="text-yellow-500 text-3xl mb-2 mx-auto" /> 
          <h2 className="text-gray-500">Account Type</h2>
          <p className="text-2xl font-bold">Student</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-8">
        <div className="bg-white rounded-lg p-6 col-span-2 shadow-md">
          <h2 className="text-lg font-semibold mb-4">Student Personality Assessment</h2>
          <div className="grid grid-cols-6 gap-4 text-center">
            <div className="flex flex-col-reverse items-center">
              <p className="h-32 bg-blue-300 w-8 mb-2 rounded-t-lg"></p>
              <p>Introverted</p>
            </div>
            <div className="flex flex-col-reverse items-center">
              <p className="h-40 bg-blue-300 w-8 mb-2 rounded-t-lg"></p>
              <p>Observant</p>
            </div>
            <div className="flex flex-col-reverse items-center">
              <p className="h-48 bg-blue-300 w-8 mb-2 rounded-t-lg"></p>
              <p>Feeling</p>
            </div>
            <div className="flex flex-col-reverse items-center">
              <p className="h-44 bg-blue-300 w-8 mb-2 rounded-t-lg"></p>
              <p>Prospecting</p>
            </div>
            <div className="flex flex-col-reverse items-center">
              <p className="h-40 bg-blue-300 w-8 mb-2 rounded-t-lg"></p>
              <p>Turbulent</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg p-6 shadow-md">
          <h2 className="text-lg font-semibold mb-4">Career Options</h2>
          <ul className="space-y-2">
            <li>Data Scientist</li>
            <li className="text-green-500">Software Developer</li>
            <li>Financial Advisor</li>
            <li>Systems Architect</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
